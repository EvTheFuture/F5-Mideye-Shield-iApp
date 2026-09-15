# How large a reported event can get.
#
# traffic_batch_size and traffic_max_buffer bound how many events are held,
# never how large one is, and the size is not ours to choose: header names come
# from the client, and _JSON_ESCAPE turns every byte outside printable ASCII
# into six. So the bound has to be in bytes, and it has to be measured against
# the worst input the code can actually be handed rather than argued about.
#
# Every limit here is read from the iRule's own RULE_INIT, so raising one and
# forgetting the consequence fails this file rather than passing quietly.
source [file join [file dirname [info script]] fp_harness.tcl]

set ::ENQUEUED [list]
proc ENQUEUE_TRAFFIC {event_json} { lappend ::ENQUEUED $event_json }
proc LOG_DEBUG {args} {}

proc clock {sub args} {
    switch -- $sub {
        seconds { return 1786000000 }
        format  { return "2026-08-13T09:00:00+0200" }
    }
}
namespace eval IP  { proc client_addr {} { return "203.0.113.7" } }
namespace eval SSL { proc cipher {args} { return $::REQ(cipher) } }
namespace eval HTTP {
    proc method  {} { return "GET" }
    proc version {} { return "1.1" }
    proc host    {} { return $::REQ(host) }
    proc path    {} { return $::REQ(path) }
    proc header {args} {
        switch -- [lindex $args 0] {
            names   { return $::REQ(hdr_order) }
            exists  { return [expr { [lsearch -exact $::REQ(hdr_order) [lindex $args 1]] >= 0 }] }
            value   {
                set k "hdr_[string tolower [lindex $args 1]]"
                if { [info exists ::REQ($k)] } { return $::REQ($k) }
                return ""
            }
        }
    }
}

set static::MIDEYE_SHIELD_traffic_enabled         1
set static::MIDEYE_SHIELD_traffic_sensor_id       "bigip-1"
set static::MIDEYE_SHIELD_traffic_device_hostname ""
set ms_traffic_ja3         "cd08e31494f9531f560d64c695473da9"
set ms_traffic_ja4         "t13d1516h2_8daaf6152771_e5627efa2ab1"
set ms_traffic_tls_version "TLSv1.3"

set MAX_EVENT   $static::MIDEYE_SHIELD_traffic_max_event
set MAX_HEADERS $static::MIDEYE_SHIELD_traffic_max_headers

# A fresh connection each time: the full shape is what carries the headers, so
# it is the shape the bound has to hold for.
proc fire_first {} {
    set ::ENQUEUED [list]
    uplevel #0 { unset -nocomplain ms_traffic_reported }
    uplevel #0 $::EVENT_BODY(HTTP_REQUEST)
    return [lindex $::ENQUEUED 0]
}

# Bytes that cost six characters each once escaped - the amplification the
# count limits cannot see.
proc hi {n} { return [string repeat \xe9 $n] }

proc set_request {host path ua cipher names} {
    array unset ::REQ
    array set ::REQ [list host $host path $path cipher $cipher hdr_order $names]
    set ::REQ(hdr_host) $host
    set ::REQ(hdr_user-agent) $ua
}

# --- an ordinary browser request is untouched by all of this ----------------
set_request "www.example.com" "/checkout" \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0" \
    "ECDHE-RSA-AES128-GCM-SHA256" \
    [list Host User-Agent Accept Accept-Language Accept-Encoding Connection Cookie]
set ::REQ(hdr_accept-language) "sv-SE,sv;q=0.9"
set typical [fire_first]
assert {$typical ne ""}                                  "a typical request still reports"
assert {[string length $typical] < 2048}                 "a typical full event stays small"
assert {[string match {*"headers":*} $typical]}          "a typical event keeps its header names"
assert {[string match {*"userAgent":*} $typical]}        "a typical event keeps its User-Agent"
assert {[string match {*"ja3":*} $typical]}              "a typical event keeps its ja3"

# --- header names at the maximum a default HTTP profile allows through ------
# 64 headers (max-header-count) of 255 high bytes each is ~16 kB on the wire,
# well inside max-header-size 32768, and escapes to ~98 kB unbounded.
set names [list]
for { set i 0 } { $i < 64 } { incr i } { lappend names "[hi 255]$i" }
set_request "www.example.com" "/" "Mozilla/5.0" "ECDHE-RSA-AES128-GCM-SHA256" $names
set heavy [fire_first]
assert {$heavy ne ""}                          "a header-heavy request still reports"
assert {[string length $heavy] <= $MAX_EVENT}  "a header-heavy event stays within traffic_max_event"
assert {[string match {*"headers":*} $heavy]}  "the header block is truncated, not discarded"
assert {[string match {*"ja4":*} $heavy]}      "the fingerprint survives truncation"

# --- every field at its cap, every byte a six-character escape --------------
# The worst input this code can be handed. Nothing oversized may reach the
# buffer, because the buffer holds up to 1000 of them for one POST body.
set_request [hi 255] "/[hi 1022]" [hi 4095] [hi 200] $names
set worst [fire_first]
assert {$worst eq ""}                    "an event over the cap never reaches the buffer"
assert {[llength $::ENQUEUED] == 0}      "nothing is enqueued for it"

# The connection is not lost with it - later requests report the slim shape,
# which carries the JA4 and so still identifies the client.
set ::ENQUEUED [list]
uplevel #0 $::EVENT_BODY(HTTP_REQUEST)
set after_drop [lindex $::ENQUEUED 0]
assert {$after_drop ne ""}                              "the connection keeps reporting after a drop"
assert {[string length $after_drop] <= $MAX_EVENT}      "the slim event is within the cap too"
assert {[string match {*"ja4":*} $after_drop]}          "a dropped full event still leaves the ja4"
assert {![string match {*"headers":*} $after_drop]}     "and does not retry the oversized shape"

# --- what the bound buys, stated in the units that matter -------------------
# _FLUSH_EVENTS puts at most 1000 events in one body, so this is the ceiling
# on a single POST. Left as an assertion so raising the cap has to be a
# deliberate change to a number someone can see.
assert {$MAX_EVENT * 1000 <= 10 * 1024 * 1024} \
    "a full batch cannot exceed 10 MB ([expr {$MAX_EVENT * 1000 / 1048576}] MB at 1000 events)"
assert {$MAX_HEADERS < $MAX_EVENT} "the header budget leaves room for the rest of the event"

finish
