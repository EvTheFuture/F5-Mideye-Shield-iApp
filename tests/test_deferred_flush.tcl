# The traffic path POSTs from CLIENT_CLOSED, not from the request that filled
# the batch, because the sideband is synchronous. These pin the wiring: what
# each path hands the buffer, and that neither can disturb the connection.
# The buffer's own behaviour is tested in test_buffer_flush.tcl.
source [file join [file dirname [info script]] fp_harness.tcl]

set ::ENQUEUED     [list]
set ::FLUSHED      [list]
set ::LOGS         [list]
set ::FLUSH_THROWS 0

proc _ENQUEUE_EVENT { sub json batch interval maxbuf } {
    set ::ENQUEUED [list $sub $batch $interval $maxbuf inline]
}
proc _ENQUEUE_EVENT_DEFERRED { sub json batch interval maxbuf } {
    set ::ENQUEUED [list $sub $batch $interval $maxbuf deferred]
}
proc _FLUSH_IF_DUE { sub batch interval maxbuf } {
    lappend ::FLUSHED [list $sub $batch $interval $maxbuf]
    if { $::FLUSH_THROWS } { error "sideband unavailable" }
}
proc LOG_DEBUG {args} { lappend ::LOGS [join $args] }

proc closed {} {
    set ::FLUSHED [list]
    set ::LOGS    [list]
    uplevel #0 $::EVENT_BODY(CLIENT_CLOSED)
}
proc logged {pattern} {
    foreach l $::LOGS { if { [string match $pattern $l] } { return 1 } }
    return 0
}

set static::MIDEYE_SHIELD_traffic_enabled        1
set static::MIDEYE_SHIELD_traffic_batch_size     200
set static::MIDEYE_SHIELD_traffic_flush_interval 10
set static::MIDEYE_SHIELD_traffic_max_buffer     1000

# --- the request path buffers and leaves --------------------------------------
ENQUEUE_TRAFFIC {{"a":1}}
assert {[lindex $::ENQUEUED 0] eq "MIDEYE_SHIELD_TRAFFIC"} \
    "traffic events go to their own subtable, not the block buffer"
assert {[lindex $::ENQUEUED 4] eq "deferred"} \
    "the request path defers the POST rather than paying for it"

# --- the close path performs it -----------------------------------------------
closed
assert {[llength $::FLUSHED] == 1}                        "CLIENT_CLOSED asks the buffer to flush"
assert {[lindex [lindex $::FLUSHED 0] 0] eq "MIDEYE_SHIELD_TRAFFIC"} "it flushes the traffic buffer"
assert {[lindex [lindex $::FLUSHED 0] 1] == 200}          "it passes the configured batch size"
assert {[lindex [lindex $::FLUSHED 0] 2] == 10}           "it passes the configured flush interval"
assert {[lindex [lindex $::FLUSHED 0] 3] == 1000}         "it passes the cap the batch size is clamped to"

# Both paths must name the same subtable, or events would be buffered in one
# place and flushed from another - a buffer nothing ever drains.
assert {[lindex $::ENQUEUED 0] eq [lindex [lindex $::FLUSHED 0] 0]} \
    "the buffer written on request is the buffer flushed on close"

# --- turned off means inert ---------------------------------------------------
set static::MIDEYE_SHIELD_traffic_enabled 0
closed
assert {[llength $::FLUSHED] == 0} "reporting turned off does no work on close"

# An unsubstituted placeholder is not 1 either. Reporting on traffic nobody
# asked to report on is the worse failure, so anything but 1 stays silent.
set static::MIDEYE_SHIELD_traffic_enabled "__traffic_enabled__"
closed
assert {[llength $::FLUSHED] == 0} "an unsubstituted placeholder does not start reporting"
set static::MIDEYE_SHIELD_traffic_enabled 1

# --- a failing flush cannot reach the connection ------------------------------
# Losing telemetry is always preferable to changing what happens to a
# connection, and a close event is no exception.
set ::FLUSH_THROWS 1
set threw [catch { closed }]
assert {$threw == 0}                       "a throwing flush does not escape CLIENT_CLOSED"
assert {[logged "*deferred flush failed*"]} "and it is not swallowed silently"
set ::FLUSH_THROWS 0

# --- nothing connection-scoped is read ----------------------------------------
# The known TMM defects here are an iRule resuming into a flow already gone, so
# the close body must touch only the session table. Read from the iRule itself,
# so a later edit reaching for the client address fails here instead.
set body $::EVENT_BODY(CLIENT_CLOSED)
foreach forbidden {IP:: TCP:: SSL:: HTTP:: clientside serverside} {
    assert {![string match "*$forbidden*" $body]} \
        "CLIENT_CLOSED does not use $forbidden, which needs a live flow"
}

finish
