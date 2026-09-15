# CLIENT_DATA must reach TCP::release whatever the fingerprinting does. A throw
# between the collect and the release leaves the connection collected and TMM
# resets it - reporting deciding a connection's fate, which is the one thing it
# must never do. These drive the real event body against stubbed iRule commands.
source [file join [file dirname [info script]] fp_harness.tcl]

namespace eval ::TCP {}
namespace eval ::IP {}

set ::RELEASED 0
set ::COLLECTS [list]
set ::PAYLOAD  ""
set ::LOGS     [list]

proc ::TCP::release {}     { incr ::RELEASED }
proc ::TCP::collect {args} { lappend ::COLLECTS $args }
proc ::TCP::payload {args} {
    if { [lindex $args 0] eq "length" } { return [string length $::PAYLOAD] }
    return $::PAYLOAD
}
proc ::IP::client_addr {} { return "192.0.2.7" }
proc LOG_DEBUG {args}     { lappend ::LOGS [join $args] }

# The body is uplevel'd, not caught here: an iRule "return" propagates as
# TCL_RETURN and ends this proc normally, so a caller's catch reports a throw
# only when the event really threw.
proc client_data {bytes} {
    set ::PAYLOAD  $bytes
    set ::RELEASED 0
    set ::COLLECTS [list]
    set ::LOGS     [list]
    set ::ms_traffic_ch_pending 1
    foreach v {ms_traffic_ja3 ms_traffic_ja4 ms_traffic_alpn ms_traffic_tls_version} {
        uplevel #0 [list unset -nocomplain $v]
    }
    uplevel #0 $::EVENT_BODY(CLIENT_DATA)
}

proc logged {pattern} {
    foreach l $::LOGS { if { [string match $pattern $l] } { return 1 } }
    return 0
}

# The event body is evaluated with "uplevel #0", so every variable an iRule
# treats as connection-scoped lands in the global namespace - "hello" included.
# The corpus is held as CORPUS so the body cannot overwrite it mid-suite.
set CORPUS [corpus_base]

# --- the ordinary path --------------------------------------------------------
assert {[catch { client_data $CORPUS }] == 0} "a well-formed hello does not throw"
assert {$::RELEASED == 1}                    "and the connection is released"
assert {[info exists ::ms_traffic_ja4]}      "and the JA4 is recorded"
assert {$::ms_traffic_ch_pending == 0}       "and the collect is marked done"

# --- a throw in the fingerprint math ------------------------------------------
# The hashing calls take the parser's own output and have no known way to throw.
# The guarantee is that being wrong about that costs telemetry, not a connection.
rename _COMPUTE_JA4 _COMPUTE_JA4_real
proc _COMPUTE_JA4 {hello_list} { error "synthetic failure" }
set threw [catch { client_data $CORPUS }]
rename _COMPUTE_JA4 ""
rename _COMPUTE_JA4_real _COMPUTE_JA4
assert {$threw == 0}                             "a throwing JA4 does not escape CLIENT_DATA"
assert {$::RELEASED == 1}                        "and the connection is still released"
assert {[logged "*ClientHello capture failed*"]} "and it is not swallowed silently"

# --- a throw in the parser ----------------------------------------------------
rename _PARSE_CLIENTHELLO _PARSE_CLIENTHELLO_real
proc _PARSE_CLIENTHELLO {payload total_needed} { error "synthetic failure" }
set threw [catch { client_data $CORPUS }]
rename _PARSE_CLIENTHELLO ""
rename _PARSE_CLIENTHELLO_real _PARSE_CLIENTHELLO
assert {$threw == 0}      "a throwing parser does not escape CLIENT_DATA"
assert {$::RELEASED == 1} "and the connection is still released"

# --- traffic that is not a TLS handshake --------------------------------------
client_data "GET / HTTP/1.1"
assert {$::RELEASED == 1}              "a non-TLS record is released, not held"
assert {$::ms_traffic_ch_pending == 0} "and the collect is not left outstanding"

# --- a record still arriving --------------------------------------------------
client_data [binary format ccc 0x16 0x03 0x01]
assert {$::RELEASED == 0}           "a record shorter than its header is not released"
assert {[llength $::COLLECTS] == 1} "it asks for more data instead"

client_data [string range $CORPUS 0 43]
assert {$::RELEASED == 0}           "an incomplete hello is not released"
assert {[llength $::COLLECTS] == 1} "it asks for the rest of the record"

finish
