# The two event shapes: the first request on a connection carries the full
# fingerprint, every later one only what can differ plus the JA4 that ties it
# back.
source [file join [file dirname [info script]] fp_harness.tcl]

# Capture what would be buffered. Batching and flushing have their own tests.
set ::ENQUEUED [list]
proc ENQUEUE_TRAFFIC {event_json} { lappend ::ENQUEUED $event_json }

# --- iRule command stubs ----------------------------------------------------
# Tcl 8.6 implements clock format on top of dict, which the harness removes;
# TMM's clock is native and unaffected. Fixing the time also keeps the event
# shape stable.
proc clock {sub args} {
    switch -- $sub {
        seconds { return 1786000000 }
        format  { return "2026-08-13T09:00:00+0200" }
    }
}

namespace eval IP  { proc client_addr {} { return "203.0.113.7%1" } }
namespace eval SSL { proc cipher {args} { return "ECDHE-RSA-AES128-GCM-SHA256" } }
namespace eval HTTP {
    proc method  {} { return $::REQ(method) }
    proc version {} { return "1.1" }
    proc host    {} { return $::REQ(host) }
    proc path    {} { return $::REQ(path) }
    proc header {args} {
        switch -- [lindex $args 0] {
            names   { return $::REQ(hdr_order) }
            exists  { return [expr { [lsearch -exact $::REQ(hdr_order) [lindex $args 1]] >= 0 }] }
            value   {
                # The fixture only stages the values a test cares about, so a
                # header with no value staged must not throw.
                set k "hdr_[string tolower [lindex $args 1]]"
                if { [info exists ::REQ($k)] } { return $::REQ($k) }
                return ""
            }
        }
    }
}

# A browser-shaped request: the header set is what makes the full event large.
proc fire_request {method host path} {
    array set ::REQ [list method $method host $host path $path]
    set ::REQ(hdr_order) [list Host User-Agent Accept Accept-Language \
        Accept-Encoding Connection Upgrade-Insecure-Requests Sec-Fetch-Dest \
        Sec-Fetch-Mode Sec-Fetch-Site Sec-Fetch-User Cache-Control \
        Cookie Authorization]
    set ::REQ(hdr_host) $host
    uplevel #0 $::EVENT_BODY(HTTP_REQUEST)
}

# --- connection state, as CLIENT_DATA would have left it --------------------
set static::MIDEYE_SHIELD_traffic_enabled     1
set static::MIDEYE_SHIELD_traffic_sensor_id   "bigip-lab-1"
set static::MIDEYE_SHIELD_traffic_device_hostname ""

set ms_traffic_ja3         "cd08e31494f9531f560d64c695473da9"
set ms_traffic_ja4         "t13d1516h2_8daaf6152771_e5627efa2ab1"
set ms_traffic_tls_version "TLSv1.3"
set ms_traffic_alpn        "h2"
set ::REQ(hdr_user-agent) "Mozilla/5.0 (Windows NT 10.0; Win64; x64)\
 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
set ::REQ(hdr_accept-language) "sv-SE,sv;q=0.9"
set ::REQ(hdr_cookie) "session=SECRETTOKEN"

# --- first request: the full fingerprint ------------------------------------
fire_request GET example.com /login
assert {[llength $::ENQUEUED] == 1} "first request enqueues one event"
set first [lindex $::ENQUEUED 0]

assert {[string match {*"ja3":"cd08e31494f9531f560d64c695473da9"*} $first]} "first carries ja3"
assert {[string match {*"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"*} $first]} "first carries ja4"
assert {[string match {*"version":"TLSv1.3"*} $first]}      "first carries TLS version"
assert {[string match {*"cipherSuite":*} $first]}           "first carries negotiated cipher"
assert {[string match {*"userAgent":*} $first]}             "first carries User-Agent"
assert {[string match {*"headers":*} $first]}               "first carries header names"
assert {[string match {*"httpVersion":"HTTP/1.1"*} $first]} "first carries HTTP version"
assert {[string match {*"ipAddress":"203.0.113.7"*} $first]} "route domain stripped from address"
assert {[string match {*"application":\{"id":"example.com"\}*} $first]} "first carries destination host"
assert {[string match {*"resource":\{"id":"/login"\}*} $first]} "first carries destination path"
assert {[string match {*"source":*} $first]}                "first carries the sensor source"

# Privacy: only Host and Accept-Language values travel. Cookie ships by name
# because its presence is the ingredient, and the denylisted headers not at all.
assert {[string match {*\{"name":"Host","value":"example.com"\}*} $first]} "Host value is sent"
assert {[string match {*\{"name":"User-Agent","value":""\}*} $first]} "other header values are empty"
assert {[string match {*\{"name":"Accept-Language","value":"sv-SE,sv;q=0.9"\}*} $first]} \
    "Accept-Language value is sent"
assert {[string match {*\{"name":"Cookie","value":""\}*} $first]} "Cookie name is reported, value empty"
assert {![string match {*SECRETTOKEN*} $first]}              "cookie value never appears in the event"
assert {![string match {*"name":"Authorization"*} $first]}  "Authorization is not reported"

# --- second request on the same connection: the slim event ------------------
set ::ENQUEUED [list]
fire_request POST example.com /admin
assert {[llength $::ENQUEUED] == 1} "second request enqueues one event"
set second [lindex $::ENQUEUED 0]

assert {[string match {*"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1"*} $second]} \
    "second keeps ja4 as the correlation key"
assert {![string match {*"ja3":*} $second]}         "second omits ja3"
assert {![string match {*"version":*} $second]}     "second omits TLS version"
assert {![string match {*"cipherSuite":*} $second]} "second omits negotiated cipher"
assert {![string match {*"userAgent":*} $second]}   "second omits User-Agent"
assert {![string match {*"headers":*} $second]}     "second omits header names"
assert {![string match {*"httpVersion":*} $second]} "second omits HTTP version"

# What varies per request must still be there - this is the point of the split.
assert {[string match {*"method":"POST"*} $second]} "second carries the method"
assert {[string match {*"resource":\{"id":"/admin"\}*} $second]} "second carries the new path"
assert {[string match {*"application":\{"id":"example.com"\}*} $second]} "second carries the host"
assert {[string match {*"source":*} $second]}       "second stays attributed to the sensor"

assert {[string length $second] * 3 < [string length $first]} \
    "slim event is under a third the size of the full one"

# --- sensor id resolution ---------------------------------------------------
# An explicit sensor id wins, then the hostname baked at deploy time, then the
# runtime hostname. The deploy-time lookup is guarded and can come up empty,
# and a default deployment must never ship unattributed.
set static::MIDEYE_SHIELD_traffic_sensor_id ""
set static::MIDEYE_SHIELD_traffic_device_hostname "bigip-unit-1.example.net"
unset ms_traffic_reported
set ::ENQUEUED [list]
fire_request GET example.com /login
assert {[string match {*"source":\{"id":"bigip-unit-1.example.net","type":"enforcement_point"\}*} \
    [lindex $::ENQUEUED 0]]} "an empty sensor id falls back to the baked device hostname"

set static::MIDEYE_SHIELD_traffic_device_hostname ""
unset ms_traffic_reported
set ::ENQUEUED [list]
fire_request GET example.com /login
set hn [info hostname]
assert {$hn ne ""} "this test needs a machine with a hostname"
assert {[string match "*\"source\":\{\"id\":\"$hn\"*" [lindex $::ENQUEUED 0]]} \
    "an empty baked hostname still attributes via the runtime hostname"

# --- a plaintext virtual server ---------------------------------------------
# SSL::cipher throws where there is no SSL context. Its own catch is there so
# that costs the cipher suite and nothing else - without it the whole event,
# including the fingerprint captured before the handshake was released, is lost.
namespace eval SSL { proc cipher {args} { error "no SSL context" } }
unset ms_traffic_reported
set ::ENQUEUED [list]
fire_request GET example.com /login
set plain [lindex $::ENQUEUED 0]
assert {[llength $::ENQUEUED] == 1}                  "a throwing SSL::cipher still reports"
assert {![string match {*"cipherSuite":*} $plain]}   "no cipher suite when there is no SSL context"
assert {[string match {*"ja4":*} $plain]}            "the fingerprint survives SSL::cipher throwing"
assert {[string match {*"headers":*} $plain]}        "the rest of the full event survives too"

finish
