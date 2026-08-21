# Drive the real _ENQUEUE_EVENT / _FLUSH_EVENTS against a modelled session
# table: batching, the two flush triggers, the overflow cap and the flush lock.
source [file join [file dirname [info script]] common_harness.tcl]

set SUB "MIDEYE_SHIELD_BLOCKS"

set ::POSTS       [list]
set ::LOGS        [list]
set ::TOKEN       "tok-123"
set ::POST_RESULT "200"
set ::STEAL_LOCK  0

set ::TOKEN_CALLS 0
proc _GET_VALID_TOKEN {} { incr ::TOKEN_CALLS; return $::TOKEN }
proc _BUILD_HSSR_ARGS {varname method uri} {
    upvar 1 $varname a
    set a [list -method $method -uri $uri]
}
proc http_req {reqargs} {
    lappend ::POSTS $reqargs
    # The POST is the only point a flush yields, so it is where a lock TTL can
    # lapse and another flusher can take over. The successor draws a real
    # ticket; a placeholder would pass even with tickets that are not unique.
    if { $::STEAL_LOCK } {
        set ::STOLEN [table incr -subtable $::SUB "ticket"]
        table set -subtable $::SUB "flush_lock" $::STOLEN indefinite indefinite
    }
    if { $::POST_RESULT eq "throw" } { error "sideband unavailable" }
    return $::POST_RESULT
}
proc LOG_WARNING {args} { lappend ::LOGS "WARNING [join $args]" }
proc LOG_DEBUG   {args} {}
proc LOG_INFO    {args} {}

# Returns "" rather than throwing when the POST never happened, so a broken
# expectation reports as one failure instead of aborting the run.
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
set static::MIDEYE_SHIELD_max_batch_bytes 921600

set ::N 200
set ::T 10
set ::MAXBUF 1000

# Seed last_flush so the timer is not already due. The cold start case has
# its own test below.
proc reset {{n 200} {t 10} {maxbuf 1000}} {
    array unset ::TBL
    array unset ::TBL_EXP
    set ::POSTS       [list]
    set ::LOGS        [list]
    set ::POST_RESULT "200"
    set ::TOKEN       "tok-123"
    set ::STEAL_LOCK  0
    set ::TOKEN_CALLS 0
    set ::N $n
    set ::T $t
    set ::MAXBUF $maxbuf
    table set -subtable $::SUB "last_flush" $::NOW indefinite indefinite
}
proc enq {json} {
    _ENQUEUE_EVENT $::SUB $json $::N $::T $::MAXBUF
}

# The traffic path: buffer here, POST from CLIENT_CLOSED instead.
proc enq_defer {json} {
    _ENQUEUE_EVENT_DEFERRED $::SUB $json $::N $::T $::MAXBUF
}

# What CLIENT_CLOSED calls.
proc closed {} {
    _FLUSH_IF_DUE $::SUB $::N $::T $::MAXBUF
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

# --- the per-event TTL must outlive the flush interval ----------------------
# A fixed TTL shorter than the interval would expire events while they wait
# out the very interval that exists to accumulate them.
reset 1000 300 1000
enq {{"a":1}}
advance 300
enq {{"a":2}}
assert {[llength $::POSTS] == 1} "a long flush interval still flushes"
assert {[post_body 0] eq {{"events":[{"a":1},{"a":2}]}}} "no event expired while waiting out a long interval"

# --- misconfiguration cannot wedge the buffer -------------------------------
# A batch size above the cap could never be reached: events drop at the cap
# long before the batch fills.
reset 5000 10 3
enq {{"a":1}}
enq {{"a":2}}
enq {{"a":3}}
assert {[llength $::POSTS] == 1} "a cap below the batch size still flushes"

# Sizes come from free-text iApp fields; a typo must fall back to the
# defaults rather than make every comparison a string comparison.
reset
set ::N "1,000"
set ::T "ten"
set ::MAXBUF ""
enq {{"a":1}}
assert {[tbl "evt_1"] ne ""} "non-numeric settings fall back instead of reporting nothing"

# --- flush lock -------------------------------------------------------------
foreach mode {1 0} {
    set ::TABLE_ADD_RETURNS_EXISTING $mode
    reset 1 10 1000
    table set -subtable $::SUB "flush_lock" "held-by-other" indefinite indefinite
    enq {{"a":1}}
    assert {[llength $::POSTS] == 0} "a held lock blocks a second flusher (table add returns existing = $mode)"
}
set ::TABLE_ADD_RETURNS_EXISTING 1

# A flusher that overran its lock has been replaced. Releasing now would
# free the new holder's lock.
reset 1 10 1000
set ::STEAL_LOCK 1
enq {{"a":1}}
assert {[tbl "flush_lock"] eq $::STOLEN} "a flusher does not release a lock it no longer holds"

# --- failure is loud --------------------------------------------------------
reset 1 10 1000
set ::POST_RESULT "500"
enq {{"a":1}}
assert {[logged "*dropped 1 event*"] == 1} "a rejected POST is reported, not swallowed"

reset 1 10 1000
set ::POST_RESULT "throw"
enq {{"a":1}}
assert {[logged "*sideband unavailable*"] == 1} "a thrown sideband error is reported"

# With no token there is no request to attempt, so the batch must survive
# the outage instead of being consumed for nothing.
reset 1 10 1000
set ::TOKEN ""
enq {{"a":1}}
assert {[logged "*no valid API token*"] == 1} "a missing token is reported"
assert {[llength $::POSTS] == 0} "no POST is attempted without a token"
assert {[tbl "cursor"] eq "" || [tbl "cursor"] == 0} "a missing token does not advance the cursor"
assert {[tbl "evt_1"] eq {{"a":1}}} "a missing token leaves the event buffered for the next flush"

# The token path leaves last_flush untouched, so the timer stays due. The
# backoff is what keeps every further event from costing a token request.
set ::LOGS [list]
enq {{"a":2}}
enq {{"a":3}}
assert {[logged "*no valid API token*"] == 0} "a token outage is not re-reported on every event"
assert {[tbl "evt_3"] eq {{"a":3}}} "events still buffer while backed off"

# Recovery must be automatic. A backoff that never expires would look like
# reporting switched off.
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

# A backoff outliving the events' TTL would expire them mid-hold and lose
# them as gaps, with no drop count and no warning.
reset 1 10 1000
set static::MIDEYE_SHIELD_api_retry_after 3600
set ::TOKEN ""
enq {{"a":1}}
set static::MIDEYE_SHIELD_api_retry_after 30
set ::TOKEN "tok-123"
advance 61
enq {{"a":2}}
assert {[llength $::POSTS] == 1} "a retry_after beyond the event TTL is clamped"
assert {[post_body 0] eq {{"events":[{"a":1},{"a":2}]}}} "the clamped backoff lifts while the held event is still alive"

# --- gaps -------------------------------------------------------------------
# Stopping at a gap would wedge the cursor permanently the first time an
# entry expired.
reset 3 10 1000
enq {{"a":1}}
enq {{"a":2}}
table delete -subtable $::SUB "evt_2"
enq {{"a":3}}
assert {[llength $::POSTS] == 1} "a missing entry does not block the flush"
assert {[post_body 0] eq {{"events":[{"a":1},{"a":3}]}}} "the gap is skipped, not sent empty"
assert {[tbl "cursor"] == 3} "the cursor advances past a gap"

# --- deferring the POST off the request path --------------------------------
# The sideband is synchronous, so whichever event flushes waits for it. The
# traffic path buffers on the request and POSTs from CLIENT_CLOSED, where no
# client is waiting. These pin that the wait actually moves.
reset 3 10 1000
enq_defer {{"a":1}}
enq_defer {{"a":2}}
enq_defer {{"a":3}}
assert {[llength $::POSTS] == 0} "a full batch does not POST from the deferring caller"
closed
assert {[llength $::POSTS] == 1} "the close event POSTs the batch"
assert {[post_body 0] eq {{"events":[{"a":1},{"a":2},{"a":3}]}}} "the deferred batch is the same body the inline path would send"

# Below both triggers there is nothing to do, and most closing connections are
# in exactly that state. A flush here would cost a POST per connection.
reset 1000 10 1000
enq_defer {{"a":1}}
closed
assert {[llength $::POSTS] == 0} "a close with the batch unfilled and the interval unelapsed does not POST"

# Every connection checks, not only one that reported. That is what drains the
# last partial batch once traffic goes quiet.
advance 10
closed
assert {[llength $::POSTS] == 1} "a close after the interval drains a partial batch"

# The common case, run by every closing connection, so it has to leave before
# anything expensive. The interval is elapsed here on purpose: that is what
# would otherwise carry it into a flush and a token lookup.
reset 1000 10 1000
advance 10
closed
assert {[llength $::POSTS] == 0}  "a close with an empty buffer does no work"
assert {$::TOKEN_CALLS == 0}      "and does not reach for a token to send nothing"

# --- deferral adds no new way to lose an event ------------------------------
# Both paths are event-driven, with no timer behind them. The inline path also
# holds a partial batch until something else happens, so deferring does not
# introduce stranding - it adds connection closes as a second way to drain.
reset 1000 10 1000
enq {{"a":1}}
advance 10
assert {[llength $::POSTS] == 0} "the inline path also holds a partial batch until the next trigger"
closed
assert {[llength $::POSTS] == 1} "and a close drains it there too"

# --- the backstop -----------------------------------------------------------
# If close-event flushes never land - a TMOS that aborts a suspended one, or a
# virtual server whose connections stay open - the buffer would fill and drop.
# From twice the batch size on, the deferring caller flushes inline instead.
reset 200 100000 1000
for { set i 1 } { $i <= 399 } { incr i } { enq_defer [format {{"a":%d}} $i] }
assert {[llength $::POSTS] == 0} "deferred events keep buffering while a close may still come"
enq_defer {{"a":400}}
assert {[llength $::POSTS] == 1} "the backstop flushes inline at twice the batch size"
assert {[tbl "dropped"] eq ""} "the backstop engages before anything is dropped"

# It has to sit above the batch size, or a deferring caller would flush from
# the request at the same count a close would. At the defaults there is room.
reset 1000 10 5000
for { set i 1 } { $i <= 1000 } { incr i } { enq_defer [format {{"a":%d}} $i] }
assert {[llength $::POSTS] == 0} "at the shipped defaults a full batch still waits for a close"
closed
assert {[llength $::POSTS] == 1} "which the close then sends"

# A cap too small for twice the batch size pulls the backstop under it, where
# the batch trigger takes over - still ahead of the first drop.
reset 1000 100000 1000
for { set i 1 } { $i <= 999 } { incr i } { enq_defer [format {{"a":%d}} $i] }
assert {[llength $::POSTS] == 0} "under the batch trigger nothing is sent"
enq_defer {{"a":1000}}
assert {[llength $::POSTS] == 1} "a cap below twice the batch size still flushes on the batch trigger"
assert {[tbl "dropped"] eq ""} "and it flushes before anything is dropped"

# Raising the cap buys headroom, not a backstop that never fires: at half of a
# large cap this would sit at 50000 events, which is no backstop at all.
reset 200 100000 100000
for { set i 1 } { $i <= 399 } { incr i } { enq_defer [format {{"a":%d}} $i] }
assert {[llength $::POSTS] == 0} "a raised cap still lets events buffer for a close"
enq_defer {{"a":400}}
assert {[llength $::POSTS] == 1} "the backstop still fires at twice the batch size under a raised cap"

# --- the interval is the other backstop -------------------------------------
# The backlog trigger catches a close path that cannot keep up; this catches
# one that is not running often enough. An event is held for 2T+60, so where
# connections outlive the interval it would expire unsent and uncounted.
reset 1000 10 1000
enq_defer {{"a":1}}
assert {[llength $::POSTS] == 0} "inside the interval the caller still defers"
advance 10
enq_defer {{"a":2}}
assert {[llength $::POSTS] == 1} "a lapsed interval stops the deferring, with no close involved"
assert {[post_body 0] eq {{"events":[{"a":1},{"a":2}]}}} "and takes the waiting event with it"

# The whole scenario rather than the trigger: a trickle of events on a virtual
# server nothing closes. Every one has to leave.
reset 1000 10 1000
for { set i 1 } { $i <= 5 } { incr i } {
    enq_defer [format {{"a":%d}} $i]
    advance 60
}
set sent ""
foreach p $::POSTS { array set o $p ; append sent $o(-body) }
for { set i 1 } { $i <= 5 } { incr i } {
    assert {[string match [format {*{"a":%d}*} $i] $sent]} \
        "event $i outlives a caller that never closes a connection"
}

# And the deferral survives it. A caller whose connections do close never
# reaches the interval on the request path, which is the entire point.
reset 1000 10 1000
set from_request 0
for { set i 1 } { $i <= 5 } { incr i } {
    set before [llength $::POSTS]
    enq_defer [format {{"a":%d}} $i]
    if { [llength $::POSTS] > $before } { incr from_request }
    advance 10
    closed
}
assert {$from_request == 0}       "closes keep the POST off the request path"
assert {[llength $::POSTS] == 5}  "and every event still leaves, one batch per close"

# Cold start: no flush has happened, so there is no interval to have lapsed.
# Due, which is what _FLUSH_IF_DUE makes of the same missing key.
reset 1000 10 1000
table delete -subtable $::SUB "last_flush"
enq_defer {{"a":1}}
assert {[llength $::POSTS] == 1} "the first event after a restart is not held for a close that may never come"

# --- _FLUSH_IF_DUE is the only definition of "due" --------------------------
# Both paths route their trigger check through it, so the deferred path cannot
# drift from the inline one. Its own inputs come from free-text iApp fields.
reset 1000 10 1000
set ::N "two hundred"
set ::T "ten"
enq_defer {{"a":1}}
closed
assert {[llength $::POSTS] == 0} "non-numeric settings fall back to defaults, not to flushing every close"
advance 10
closed
assert {[llength $::POSTS] == 1} "the default interval still drains the buffer"

# --- the byte cap ------------------------------------------------------------
# 1000 events is the API's count limit, not a size limit, so a batch of large
# events reaches megabytes. A body an ingress refuses is lost outright: the
# buffer is consumed before the POST, so there is nothing left to retry.
proc ev {n} { return "\{\"e\":\"[string repeat x $n]\"\}" }

# What one event costs in the body: itself, plus the comma the join adds.
set ::EVCOST [expr { [string length [ev 100]] + 1 }]

proc cap {events} {
    set static::MIDEYE_SHIELD_max_batch_bytes [expr { $::EVCOST * $events }]
}

# A batch inside the cap is untouched by it.
cap 100
reset 1000 10 5000
for { set i 1 } { $i <= 5 } { incr i } { enq [ev 100] }
_FLUSH_EVENTS $::SUB
assert {[tbl "cursor"] == 5} "a batch within the cap is taken whole"

# Over the cap, the flush takes what fits and leaves the rest where it is.
cap 3
reset 1000 10 5000
for { set i 1 } { $i <= 10 } { incr i } { enq [ev 100] }
assert {[llength $::POSTS] == 0} "neither trigger is due, so all ten are still buffered"

_FLUSH_EVENTS $::SUB
assert {[llength $::POSTS] == 1}          "an oversized batch still POSTs"
assert {[tbl "cursor"] == 3}              "the cursor tracks what was taken, not what was offered"
assert {[string length [post_body 0]] <= [expr { $::EVCOST * 3 + 13 }]} \
    "the body holds three events and the {\"events\":\[\]} wrapper"
assert {[tbl "evt_3"] eq ""}              "what went is deleted"
assert {[tbl "evt_4"] ne ""}              "what did not fit is kept, not dropped"

# The remainder is not stranded: later flushes resume from the cursor.
_FLUSH_EVENTS $::SUB
assert {[tbl "cursor"] == 6} "the next flush resumes where the last one stopped"
_FLUSH_EVENTS $::SUB
_FLUSH_EVENTS $::SUB
assert {[tbl "cursor"] == 10}         "every event leaves eventually"
assert {[llength $::POSTS] == 4}      "split across four bodies rather than one oversized body"

# A gap inside a capped batch is consumed with it. Leaving TAKEN behind on the
# skip would stall the cursor on an event that no longer exists.
cap 3
reset 1000 10 5000
for { set i 1 } { $i <= 6 } { incr i } { enq [ev 100] }
table delete -subtable $::SUB "evt_2"
_FLUSH_EVENTS $::SUB
assert {[tbl "cursor"] == 4} "an expired event is passed over inside the cap, not left to block it"

# One event bigger than the whole cap still goes, or nothing behind it could.
# Not "cap 0": a cap below 1 is not believed, and falls back to the default.
set static::MIDEYE_SHIELD_max_batch_bytes 10
reset 1000 10 5000
enq [ev 100]
_FLUSH_EVENTS $::SUB
assert {[llength $::POSTS] == 1} "an event larger than the cap is sent rather than held forever"
assert {[tbl "cursor"] == 1}     "and the cursor moves past it"

# The cap is a static, not a form field, but a hand-edited iRule can still
# break it and must not take the flush down with it.
set static::MIDEYE_SHIELD_max_batch_bytes "nine hundred kilobytes"
reset 1000 10 5000
enq [ev 100]
_FLUSH_EVENTS $::SUB
assert {[llength $::POSTS] == 1} "a non-numeric cap falls back to the default instead of throwing"

set static::MIDEYE_SHIELD_max_batch_bytes 921600

finish
