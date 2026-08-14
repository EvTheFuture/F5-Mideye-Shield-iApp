# What reaches /ips/events when the BIG-IP refuses a connection, and which
# denials must never produce an event. No innocent IP may be reported as
# blocked.
source [file join [file dirname [info script]] common_harness.tcl]

set SUB "MIDEYE_SHIELD_BLOCKS"

set ::BLACKLIST 0
set ::WHITELIST 0
set ::SCORE     0

proc LOG_WARNING {args} {}
proc LOG_INFO    {args} {}
proc LOG_DEBUG   {args} {}
proc class {op value cmp dg} {
    if { [string match "*BLACKLIST" $dg] } { return $::BLACKLIST }
    if { [string match "*WHITELIST" $dg] } { return $::WHITELIST }
    return 0
}
proc _FETCH_IP_SCORE {client_ip cache_time} { return $::SCORE }

# Capture what would be buffered. Batching and flushing have their own tests.
set ::ENQUEUED [list]
proc _ENQUEUE_EVENT {sub event_json batch_size flush_interval max_buffer} {
    lappend ::ENQUEUED [list $sub $event_json]
}

set static::MIDEYE_SHIELD_score_hard_deny      80
set static::MIDEYE_SHIELD_score_warn           50
set static::MIDEYE_SHIELD_block_batch_size     200
set static::MIDEYE_SHIELD_block_flush_interval 10
set static::MIDEYE_SHIELD_block_max_buffer     1000

# Every flag a test flips is restored here. A leaked disabled or
# block_enabled 0 would make every "reports nothing" assertion pass for free.
proc reset {{dry 0}} {
    array unset ::TBL
    array unset ::TBL_EXP
    set ::ENQUEUED  [list]
    set ::BLACKLIST 0
    set ::WHITELIST 0
    set ::SCORE     0
    set ::VIRTUAL_NAME "/Common/vs_test"
    set static::MIDEYE_SHIELD_dry_run        $dry
    set static::MIDEYE_SHIELD_disabled       0
    set static::MIDEYE_SHIELD_block_enabled  1
}
proc evt {i} { return [lindex [lindex $::ENQUEUED $i] 1] }
proc evt_sub {i} { return [lindex [lindex $::ENQUEUED $i] 0] }

# --- score deny reports -----------------------------------------------------
reset
set ::SCORE 90
_VALIDATE 1.2.3.4 300
assert {[llength $::ENQUEUED] == 1} "a score deny enqueues exactly one event"
assert {[evt_sub 0] eq $SUB} "block events use their own subtable"
assert {[string match {*"ipAddress":"1.2.3.4"*} [evt 0]]} "event carries the client IP"
assert {[string match {*"outcome":"blocked"*} [evt 0]]} "outcome is blocked"
assert {[string match {*"observedAt":"2026-08-14T09:00:00+0200"*} [evt 0]]} "event is stamped when it happened"
assert {[string match {*"name":"score_hard_deny"*} [evt 0]]} "score deny is named"
assert {[string match {*"id":"/Common/vs_test"*} [evt 0]]} "enforcedBy.id is the virtual server"
assert {[string match {*"type":"irule"*} [evt 0]]} "enforcedBy.type is irule"
assert {[string match {*"provider":"f5_bigip"*} [evt 0]]} "enforcedBy.provider is f5_bigip"

# --- blacklist deny reports, distinguishably --------------------------------
reset
set ::BLACKLIST 1
_VALIDATE 1.2.3.4 300
assert {[llength $::ENQUEUED] == 1} "a blacklist deny enqueues exactly one event"
assert {[string match {*"name":"blacklist"*} [evt 0]]} "blacklist deny is named apart from a score deny"

# --- what must NEVER be reported --------------------------------------------
# A full pending queue is a capacity deny of a possibly innocent IP.
reset
set ::SCORE -3
_VALIDATE 1.2.3.4 300
assert {[llength $::ENQUEUED] == 0} "a full pending queue reports nothing"

reset 1
set ::SCORE 90
_VALIDATE 1.2.3.4 300
assert {[llength $::ENQUEUED] == 0} "dry run reports no score deny"

reset 1
set ::BLACKLIST 1
_VALIDATE 1.2.3.4 300
assert {[llength $::ENQUEUED] == 0} "dry run reports no blacklist deny"

reset
set ::SCORE -2
_VALIDATE 1.2.3.4 300
assert {[llength $::ENQUEUED] == 0} "an API failure fails open and reports nothing"

reset
set ::SCORE 10
_VALIDATE 1.2.3.4 300
assert {[llength $::ENQUEUED] == 0} "an allowed IP reports nothing"

# The score would deny on its own, so this fails if the whitelist stops
# taking precedence.
reset
set ::WHITELIST 1
set ::SCORE 90
_VALIDATE 1.2.3.4 300
assert {[llength $::ENQUEUED] == 0} "a whitelisted IP reports nothing"

reset
set static::MIDEYE_SHIELD_disabled 1
set ::SCORE 90
_VALIDATE 1.2.3.4 300
assert {[llength $::ENQUEUED] == 0} "a disabled Shield reports nothing"

reset
set static::MIDEYE_SHIELD_block_enabled 0
set ::SCORE 90
_VALIDATE 1.2.3.4 300
assert {[llength $::ENQUEUED] == 0} "reporting turned off reports nothing"

# --- enforcedBy.id fallback -------------------------------------------------
# enforcedBy.id is required and non-empty in the API schema. An empty virtual
# name would fail validation for the whole batch.
reset
set ::VIRTUAL_NAME ""
set ::SCORE 90
_VALIDATE 1.2.3.4 300
assert {[string match {*"id":"mideye_shield"*} [evt 0]]} "enforcedBy.id falls back when virtual name is empty"

# --- the builder must actually escape what it interpolates ------------------
# _JSON_ESCAPE in isolation says nothing about whether the event builder
# calls it. Hostile bytes are built with format %c to keep literal
# backslashes out of this file.
reset
set Q [format %c 34]
set B [format %c 92]
set ::VIRTUAL_NAME "/Common/vs${Q}${B}x"
set ::SCORE 90
_VALIDATE 1.2.3.4 300
set want "${Q}id${Q}:${Q}/Common/vs${B}${Q}${B}${B}x${Q}"
assert {[string first $want [evt 0]] >= 0} "the event builder escapes quotes and backslashes it interpolates"

finish
