# Drive the real _ENQUEUE_EVENT / _FLUSH_EVENTS against a modelled session
# table: batching, the two flush triggers, the overflow cap and the flush lock.
# Every failure here costs other clients' buffered events, not just the one that
# provoked it.
source [file join [file dirname [info script]] common_harness.tcl]

set SUB "MIDEYE_SHIELD_BLOCKS"

set ::POSTS       [list]
set ::LOGS        [list]
set ::TOKEN       "tok-123"
set ::POST_RESULT "200"
set ::STEAL_LOCK  0

proc _GET_VALID_TOKEN {} { return $::TOKEN }
proc _BUILD_HSSR_ARGS {varname method uri} {
    upvar 1 $varname a
    set a [list -method $method -uri $uri]
}
proc http_req {reqargs} {
    lappend ::POSTS $reqargs
    # The POST is the only point a flush yields, so it is where a lock TTL can
    # lapse and a second flusher can take over. Model that here.
    if { $::STEAL_LOCK } {
        table set -subtable $::SUB "flush_lock" "someone-else" indefinite indefinite
    }
    if { $::POST_RESULT eq "throw" } { error "sideband unavailable" }
    return $::POST_RESULT
}
proc LOG_WARNING {args} { lappend ::LOGS "WARNING [join $args]" }
proc LOG_DEBUG   {args} {}
proc LOG_INFO    {args} {}

# Returns "" rather than throwing when the POST never happened, so one broken
# expectation reports as a single failure instead of aborting the whole run.
proc post_body {i} {
    array set o [lindex $::POSTS $i]
    if { [info exists o(-body)] } { return $o(-body) }
    return ""
}
proc logged {pattern} {
    foreach l $::LOGS { if { [string match $pattern $l] } { return 1 } }
    return 0
}
proc tbl {key} { return [table lookup -subtable $::SUB $key] }

set static::MIDEYE_SHIELD_api_timeout     5000
set static::MIDEYE_SHIELD_api_base_url    "https://shield.example.com/api"
set static::MIDEYE_SHIELD_api_retry_after 30

set ::N 200
set ::T 10
set ::MAXBUF 1000

# Seed last_flush so the timer is not already due; the cold-start case where it
# is unset gets its own test below.
proc reset {{n 200} {t 10} {maxbuf 1000}} {
    array unset ::TBL
    array unset ::TBL_EXP
    set ::POSTS       [list]
    set ::LOGS        [list]
    set ::POST_RESULT "200"
    set ::TOKEN       "tok-123"
    set ::STEAL_LOCK  0
    set ::N $n
    set ::T $t
    set ::MAXBUF $maxbuf
    table set -subtable $::SUB "last_flush" $::NOW indefinite indefinite
}
proc enq {json} {
    _ENQUEUE_EVENT $::SUB $json $::N $::T $::MAXBUF
}

# --- batching ---------------------------------------------------------------
reset 3 10 1000
enq {{"a":1}}
enq {{"a":2}}
assert {[llength $::POSTS] == 0} "no POST before the batch is full"
enq {{"a":3}}
assert {[llength $::POSTS] == 1} "batch size triggers exactly one POST"
assert {[post_body 0] eq {{"events":[{"a":1},{"a":2},{"a":3}]}}} "batch body is one events array in order"
assert {[tbl "cursor"] == 3} "cursor advances to the flushed sequence"

# --- time trigger -----------------------------------------------------------
reset 1000 10 1000
enq {{"a":1}}
assert {[llength $::POSTS] == 0} "no POST while under batch size and inside the interval"
advance 10
enq {{"a":2}}
assert {[llength $::POSTS] == 1} "elapsed interval triggers a flush on the next event"

# --- cold start -------------------------------------------------------------
# An unset last_flush reads as long overdue, so the first event flushes rather
# than waiting out an interval that never started.
reset 1000 10 1000
table delete -subtable $::SUB "last_flush"
enq {{"a":1}}
assert {[llength $::POSTS] == 1} "an unset last_flush flushes on the first event"

# --- overflow ---------------------------------------------------------------
# The cursor only advances in _FLUSH_EVENTS, so a buffer can only grow past the
# cap while another flusher holds the lock. That is the only path to a drop.
reset 1000 10 3
table set -subtable $::SUB "flush_lock" "held-by-other" indefinite indefinite
enq {{"a":1}}
enq {{"a":2}}
enq {{"a":3}}
enq {{"a":4}}
enq {{"a":5}}
assert {[llength $::POSTS] == 0} "a held lock leaves the buffer to grow"
assert {[tbl "dropped"] ne "" && [tbl "dropped"] > 0} "events over the cap are dropped and counted"
table delete -subtable $::SUB "flush_lock"
advance 10
enq {{"a":6}}
assert {[logged "*buffer full*"] == 1} "an overflowing buffer says so"

# --- per-request cap --------------------------------------------------------
# The Shield API takes at most 1000 events per request, so a backlog has to go
# out in slices rather than in one oversized POST.
reset 100000 10 5000
for { set i 1 } { $i <= 1002 } { incr i } { enq [format {{"a":%d}} $i] }
assert {[llength $::POSTS] == 0} "a backlog under the batch size does not flush"
advance 10
enq [format {{"a":%d}} 1003]
assert {[llength $::POSTS] == 1} "the elapsed interval flushes the backlog"
assert {[tbl "cursor"] == 1000} "a flush sends at most 1000 events"

# --- flush lock -------------------------------------------------------------
foreach mode {1 0} {
    set ::TABLE_ADD_RETURNS_EXISTING $mode
    reset 1 10 1000
    table set -subtable $::SUB "flush_lock" "held-by-other" indefinite indefinite
    enq {{"a":1}}
    assert {[llength $::POSTS] == 0} "a held lock blocks a second flusher (table add returns existing = $mode)"
}
set ::TABLE_ADD_RETURNS_EXISTING 1

# A flusher that overran its lock has been replaced; releasing then would free
# THEIR lock and let a third run alongside them.
reset 1 10 1000
set ::STEAL_LOCK 1
enq {{"a":1}}
assert {[tbl "flush_lock"] eq "someone-else"} "a flusher does not release a lock it no longer holds"

# --- failure is loud --------------------------------------------------------
reset 1 10 1000
set ::POST_RESULT "500"
enq {{"a":1}}
assert {[logged "*dropped 1 event*"] == 1} "a rejected POST is reported, not swallowed"

reset 1 10 1000
set ::POST_RESULT "throw"
enq {{"a":1}}
assert {[logged "*sideband unavailable*"] == 1} "a thrown sideband error is reported"

# No token means no request to attempt, so the batch must survive: consuming it
# anyway would lose 100% of blocked events for the length of a token outage.
reset 1 10 1000
set ::TOKEN ""
enq {{"a":1}}
assert {[logged "*no valid API token*"] == 1} "a missing token is reported"
assert {[llength $::POSTS] == 0} "no POST is attempted without a token"
assert {[tbl "cursor"] eq "" || [tbl "cursor"] == 0} "a missing token does not advance the cursor"
assert {[tbl "evt_1"] eq {{"a":1}}} "a missing token leaves the event buffered for the next flush"

# The token path is the one exit that leaves last_flush untouched, so the timer
# stays due; unthrottled, every further event would cost another token request
# on the same sideband path score lookups use.
set ::LOGS [list]
enq {{"a":2}}
enq {{"a":3}}
assert {[logged "*no valid API token*"] == 0} "a token outage is not re-reported on every event"
assert {[tbl "evt_3"] eq {{"a":3}}} "events still buffer while backed off"

# Recovery has to be automatic: a backoff that outlived the outage would be
# indistinguishable from reporting being switched off.
set ::TOKEN "tok-123"
enq {{"a":4}}
assert {[llength $::POSTS] == 0} "the backoff still holds before it expires"
advance 31
enq {{"a":5}}
assert {[llength $::POSTS] == 1} "flushing resumes once the backoff expires"
assert {[post_body 0] eq {{"events":[{"a":1},{"a":2},{"a":3},{"a":4},{"a":5}]}}} "every event held during the outage is sent"

# An unusable retry_after must not disable reporting outright.
reset 1 10 1000
set static::MIDEYE_SHIELD_api_retry_after "not a number"
set ::TOKEN ""
enq {{"a":1}}
set static::MIDEYE_SHIELD_api_retry_after 30
set ::TOKEN "tok-123"
advance 31
enq {{"a":2}}
assert {[llength $::POSTS] == 1} "a non-numeric retry_after falls back to the default backoff"

# --- gaps -------------------------------------------------------------------
# Stopping at a gap would wedge the cursor permanently the first time an entry
# expired, which costs far more than the rare event lost to that race.
reset 3 10 1000
enq {{"a":1}}
enq {{"a":2}}
table delete -subtable $::SUB "evt_2"
enq {{"a":3}}
assert {[llength $::POSTS] == 1} "a missing entry does not block the flush"
assert {[post_body 0] eq {{"events":[{"a":1},{"a":3}]}}} "the gap is skipped, not sent empty"
assert {[tbl "cursor"] == 3} "the cursor advances past a gap"

finish
