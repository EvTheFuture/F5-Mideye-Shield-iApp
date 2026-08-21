# =============================================================================
# iRule   : MIDEYE_SHIELD_TRAFFIC
# Version : 0.1.0
# Author  : Mideye
# Date    : 2026-08-17
#
# Purpose
# -------
# This iRule reports TLS and HTTP client fingerprints for all traffic reaching
# a protected Virtual Server, not only for authentication attempts. JA3 and JA4
# are computed from the raw ClientHello; the first HTTP request on a connection
# also reports its shape, every later request only what can differ.
#
# Apply this iRule where the client speaks first - TLS, and HTTP over it.
# CLIENT_ACCEPTED collects the handshake, which holds the serverside connection
# back until the client sends, so a server-first protocol (SSH, SMTP, FTP)
# hangs until the TCP profile times it out. See docs/traffic-intelligence.md.
#
# Reporting is on by default and can be turned off in the iApp, which leaves
# the iRule loaded but inert. When it shares a Virtual Server with
# MIDEYE_SHIELD_CONNECTION, list it after that iRule so the enforcement
# decision completes first.
#
# See docs/traffic-intelligence.md for the event shape and the design notes.
#
#
# Privacy
# -------
# Header NAMES are reported in the order the client sent them, header VALUES
# only for Host, Accept-Language and User-Agent. Paths are reported without
# their query string, and headers in traffic_forbidden_headers not at all.
# docs/traffic-intelligence.md lists everything that leaves the device.
#
#
# Dependencies - iRules (call targets)
# -------------------------------------
#   /__partition__/MIDEYE_SHIELD_COMMON
#       Shared library: _ENQUEUE_EVENT, _JSON_ESCAPE and LOG_*. The traffic_*
#       settings are declared in its RULE_INIT.
#
#
# Dependencies - Session Table (subtable)
# ----------------------------------------
# Buffered events live in "MIDEYE_SHIELD_TRAFFIC", written only by COMMON's
# event buffer procs. See MIDEYE_SHIELD_COMMON for the key conventions.
#
#
# Provenance
# ----------
# The ClientHello parsing is adapted from f5devcentral/f5-ja4 and redistributed
# under the BSD 3-Clause terms below, which that license requires source
# redistributions to retain. JA3 is reimplemented from Salesforce's published
# method rather than copied. The JA4+ variants (JA4H, JA4S, JA4L, ...) are
# under the separate FoxIO License 1.1 and are not implemented here.
#
#   Copyright (c) 2024, FoxIO
#   All rights reserved.
#   Software: JA4 (TLS client fingerprinting)
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
#   * Neither the name of FoxIO nor the names of its contributors may be used
#     to endorse or promote products derived from this software without
#     specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
#   PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
#   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# =============================================================================

when RULE_INIT {
    # Parsing limits, not iApp settings. The user-facing traffic_* settings are
    # declared in MIDEYE_SHIELD_COMMON's RULE_INIT.
    set static::MIDEYE_SHIELD_traffic_max_record 17408
    set static::MIDEYE_SHIELD_traffic_max_iter   256

    # Byte bounds on one event. The batch settings bound how MANY events are
    # held, never how large they are, and size is not ours to choose: header
    # names come from the client and every byte outside printable ASCII escapes
    # to six. Without these, a request inside the HTTP profile's own default
    # limits inflates an event past 100 kB and a full batch past 100 MB.
    set static::MIDEYE_SHIELD_traffic_max_headers 2048
    set static::MIDEYE_SHIELD_traffic_max_event   8192

    # Never reported, not even by name. Cookie is absent on purpose: its
    # presence is a fingerprint ingredient and its value is never read.
    set static::MIDEYE_SHIELD_traffic_forbidden_headers "authorization set-cookie x-api-key x-auth-token proxy-authorization x-csrf-token x-xsrf-token"
}

# ===========================================================================
# P R I V A T E   P R O C E D U R E S
# ===========================================================================

# ---------------------------------------------------------------------------
# proc: _HEADER_VALUE_CAP
#
# How much of a header's value may be reported, as the last index to keep, or
# "" to report the name only. The caller tests the name before fetching the
# value, so "" means the value is never read at all.
#
# One cap for both: Host already leaves as destination.application.id, and
# Accept-Language is bounded to match rather than for a reason of its own.
# ---------------------------------------------------------------------------
proc _HEADER_VALUE_CAP { name } {
    switch -- [string tolower $name] {
        "host"            { return 255 }
        "accept-language" { return 255 }
        default           { return "" }
    }
}

# ---------------------------------------------------------------------------
# proc: _MAP_HTTP_VERSION
#
# Map an [HTTP::version] value to the Shield API httpVersion enum, or "" when
# it is not one of the accepted values (the field is optional - omit it).
# ---------------------------------------------------------------------------
proc _MAP_HTTP_VERSION { v } {
    switch -- $v {
        "1.0"   { return "HTTP/1.0" }
        "1.1"   { return "HTTP/1.1" }
        "2.0"   { return "HTTP/2" }
        "2"     { return "HTTP/2" }
        "3.0"   { return "HTTP/3" }
        "3"     { return "HTTP/3" }
        default { return "" }
    }
}

# ---------------------------------------------------------------------------
# proc: _MAP_TLS_VERSION
#
# Map a JA4 2-char version code to the Shield API tlsVersion enum, or "" when
# unknown (the field is optional - omit it).
# ---------------------------------------------------------------------------
proc _MAP_TLS_VERSION { v2 } {
    switch -- $v2 {
        "13"    { return "TLSv1.3" }
        "12"    { return "TLSv1.2" }
        "11"    { return "TLSv1.1" }
        "10"    { return "TLSv1.0" }
        default { return "" }
    }
}

# ---------------------------------------------------------------------------
# proc: _U16_VECTOR
#
# Read a TLS vector of 16-bit values - a length prefix of len_bytes (1 or 2)
# followed by that many bytes of entries - and return them as 4-char hex with
# GREASE removed. Returns "" when the vector does not fit within limit, which
# callers treat as the extension being absent.
#
# Extensions 000a, 000d and 002b are this shape, differing only in prefix width.
# ---------------------------------------------------------------------------
proc _U16_VECTOR { payload off limit len_bytes } {
    if { $off + $len_bytes > $limit } { return "" }
    if { $len_bytes == 1 } {
        binary scan $payload @${off}c vec_len
        set vec_len [expr { $vec_len & 0xff }]
    } else {
        binary scan $payload @${off}S vec_len
        set vec_len [expr { $vec_len & 0xffff }]
    }

    set pos [expr { $off + $len_bytes }]
    set end [expr { $pos + $vec_len }]
    if { ($vec_len % 2) != 0 || $end > $limit } { return "" }

    set out  [list]
    set iter 0
    while { $pos + 2 <= $end } {
        if { [incr iter] > $static::MIDEYE_SHIELD_traffic_max_iter } { break }
        unset -nocomplain entry_hex
        binary scan $payload @${pos}H4 entry_hex
        if { ![info exists entry_hex] || [string length $entry_hex] != 4 } { break }
        set entry [scan $entry_hex %x]
        incr pos 2
        if { ($entry & 0x0f0f) == 0x0a0a && (($entry >> 8) & 0xff) == ($entry & 0xff) } { continue }
        lappend out $entry_hex
    }
    return $out
}

# ---------------------------------------------------------------------------
# proc: _ALPN_2CHAR
#
# The JA4 ALPN field: first and last character of the offered protocol, or the
# first and last nibble of its hex encoding when either is outside [0-9A-Za-z].
# "00" when nothing was offered. The range test is explicit because
# `string is alnum` is Unicode-aware and would accept high bytes.
# ---------------------------------------------------------------------------
proc _ALPN_2CHAR { proto } {
    if { [string length $proto] < 1 } { return "00" }

    set first [string index $proto 0]
    set last  [string index $proto end]
    set fb [scan $first %c]
    set lb [scan $last %c]
    set first_ok [expr { ($fb >= 0x30 && $fb <= 0x39) || ($fb >= 0x41 && $fb <= 0x5A) || ($fb >= 0x61 && $fb <= 0x7A) }]
    set last_ok  [expr { ($lb >= 0x30 && $lb <= 0x39) || ($lb >= 0x41 && $lb <= 0x5A) || ($lb >= 0x61 && $lb <= 0x7A) }]
    if { $first_ok && $last_ok } {
        return "${first}${last}"
    }

    binary scan $proto H* hex
    return "[string index $hex 0][string index $hex end]"
}

# ---------------------------------------------------------------------------
# proc: _U8_VECTOR
#
# Read a TLS vector of single-byte values - a 1-byte length prefix followed by
# that many bytes - and return them as decimals. Returns "" when the vector
# does not fit within limit. Used for 000b, whose single-byte values cannot
# carry GREASE.
# ---------------------------------------------------------------------------
proc _U8_VECTOR { payload off limit } {
    if { $off + 1 > $limit } { return "" }
    binary scan $payload @${off}c vec_len
    set vec_len [expr { $vec_len & 0xff }]

    set pos [expr { $off + 1 }]
    set end [expr { $pos + $vec_len }]
    if { $end > $limit } { return "" }

    set out  [list]
    set iter 0
    while { $pos < $end } {
        if { [incr iter] > $static::MIDEYE_SHIELD_traffic_max_iter } { break }
        binary scan $payload @${pos}c entry
        lappend out [expr { $entry & 0xff }]
        incr pos
    }
    return $out
}

# ---------------------------------------------------------------------------
# proc: _PARSE_CLIENTHELLO
#
# Parse a fully collected TLS ClientHello record into a name/value list of the
# fields JA3 and JA4 need, with GREASE (RFC 8701) stripped. Returns "" if the
# payload is not a ClientHello or is malformed.
#
# Adapted from f5devcentral/f5-ja4, extended with the decimal lists JA3 needs.
# ---------------------------------------------------------------------------
proc _PARSE_CLIENTHELLO { payload total_needed } {
    binary scan $payload @5c handshake_type
    set handshake_type [expr { $handshake_type & 0xff }]
    if { $handshake_type != 0x01 } {
        return ""
    }

    # The handshake must fit inside this record. A ClientHello fragmented across
    # records would otherwise fingerprint from its first part - stable, but wrong.
    binary scan $payload @6H6 hs_len_hex
    if { [scan $hs_len_hex %x] != ($total_needed - 9) } {
        return ""
    }

    # Legacy client_version at offset 9 (JA3 keys on this; JA4 overrides it
    # from the supported_versions extension when present).
    binary scan $payload @9H4 ver_hex

    set max_iter $static::MIDEYE_SHIELD_traffic_max_iter

    # 32-byte random follows the 2-byte version; session id starts at 43.
    set off 43
    if { $off >= $total_needed } { return "" }
    binary scan $payload @${off}c sessid_len
    set sessid_len [expr { $sessid_len & 0xff }]
    set off [expr { $off + 1 + $sessid_len }]
    if { $off + 2 > $total_needed } { return "" }

    binary scan $payload @${off}S cs_length
    set cs_length [expr { $cs_length & 0xffff }]
    incr off 2
    if { ($cs_length % 2) != 0 || $off + $cs_length > $total_needed } {
        return ""
    }
    set cs_end [expr { $off + $cs_length }]
    set ciphers_hex [list]
    set cs_iter 0
    while { $off < $cs_end } {
        if { [incr cs_iter] > $max_iter } { break }
        unset -nocomplain cs_hex
        binary scan $payload @${off}H4 cs_hex
        if { ![info exists cs_hex] || [string length $cs_hex] != 4 } { break }
        set cs_int [scan $cs_hex %x]
        incr off 2
        if { ($cs_int & 0x0f0f) == 0x0a0a && (($cs_int >> 8) & 0xff) == ($cs_int & 0xff) } {
            continue
        }
        lappend ciphers_hex $cs_hex
    }
    set off $cs_end

    if { $off + 1 > $total_needed } { return "" }
    binary scan $payload @${off}c comp_len
    set comp_len [expr { $comp_len & 0xff }]
    set off [expr { $off + 1 + $comp_len }]

    set has_sni       0
    set alpn_2char    "00"
    set alpn_proto    ""
    # Always TCP: this iRule fingerprints from TCP::collect, so QUIC ("q")
    # cannot occur here.
    set ja4_tprt      "t"
    set ver_2char_src $ver_hex
    set exts_hex      [list]
    set curves_dec    [list]
    set pointfmts_dec [list]
    set sigalgs_hex   [list]

    # Extensions are optional, but one running past the record - the block or a
    # single extension - means the hello contradicts its own length fields.
    # Reject the whole parse: a partial extension list still hashes to a
    # confident, stable, wrong fingerprint.
    if { $off + 2 <= $total_needed } {
        binary scan $payload @${off}S ext_total_len
        set ext_total_len [expr { $ext_total_len & 0xffff }]
        incr off 2
        if { $off + $ext_total_len <= $total_needed } {
            set ext_end [expr { $off + $ext_total_len }]
            set ext_iter 0
            while { $off + 4 <= $ext_end } {
                if { [incr ext_iter] > $max_iter } { break }
                unset -nocomplain et_hex
                binary scan $payload @${off}H4 et_hex
                if { ![info exists et_hex] || [string length $et_hex] != 4 } { break }
                set et_int [scan $et_hex %x]
                incr off 2
                binary scan $payload @${off}S et_len
                set et_len [expr { $et_len & 0xffff }]
                incr off 2
                set data_start $off
                if { $et_len < 0 || $data_start + $et_len > $ext_end } { return "" }

                # RFC 8446: an extension type may appear at most once. A hello
                # that repeats one would have its vectors counted twice and
                # fingerprint as something no client sends.
                if { [info exists ext_seen($et_hex)] } { return "" }
                set ext_seen($et_hex) 1

                if { ($et_int & 0x0f0f) == 0x0a0a && (($et_int >> 8) & 0xff) == ($et_int & 0xff) } {
                    set off [expr { $data_start + $et_len }]
                    continue
                }
                lappend exts_hex $et_hex
                switch $et_hex {
                    "0000" {
                        set has_sni 1
                    }
                    "000a" {
                        foreach curve [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_U16_VECTOR \
                                $payload $data_start [expr { $data_start + $et_len }] 2] {
                            lappend curves_dec [scan $curve %x]
                        }
                    }
                    "000b" {
                        foreach fmt [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_U8_VECTOR \
                                $payload $data_start [expr { $data_start + $et_len }]] {
                            lappend pointfmts_dec $fmt
                        }
                    }
                    "000d" {
                        foreach sigalg [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_U16_VECTOR \
                                $payload $data_start [expr { $data_start + $et_len }] 2] {
                            lappend sigalgs_hex $sigalg
                        }
                    }
                    "0010" {
                        if { $et_len >= 4 } {
                            binary scan $payload @[expr {$data_start + 2}]c alpn_str_len
                            set alpn_str_len [expr { $alpn_str_len & 0xff }]
                            if { $alpn_str_len > 0 && $alpn_str_len + 3 <= $et_len } {
                                binary scan $payload @[expr {$data_start + 3}]a${alpn_str_len} alpn_proto
                                set alpn_2char [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_ALPN_2CHAR $alpn_proto]
                            }
                        }
                    }
                    "002b" {
                        # Highest offered version wins; lsort on 4-char hex is
                        # numeric order here.
                        set offered [lsort [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_U16_VECTOR \
                            $payload $data_start [expr { $data_start + $et_len }] 1]]
                        if { [llength $offered] > 0 } {
                            set ver_2char_src [lindex $offered end]
                        }
                    }
                }
                set off [expr { $data_start + $et_len }]
            }
        } else {
            return ""
        }
    } elseif { $off != $total_needed } {
        return ""
    }

    switch $ver_2char_src {
        "0304"  { set ver_2char "13" }
        "0303"  { set ver_2char "12" }
        "0302"  { set ver_2char "11" }
        "0301"  { set ver_2char "10" }
        "0300"  { set ver_2char "s3" }
        default { set ver_2char "00" }
    }

    # TMM has no `dict`, so the fields come back as a flat name/value list the
    # caller reloads with `array set`. List-valued fields round-trip intact.
    set out(ver_hex)       $ver_hex
    set out(ver_2char)     $ver_2char
    set out(tprt)          $ja4_tprt
    set out(has_sni)       $has_sni
    set out(alpn_2char)    $alpn_2char
    set out(alpn_proto)    $alpn_proto
    set out(ciphers_hex)   $ciphers_hex
    set out(exts_hex)      $exts_hex
    set out(curves_dec)    $curves_dec
    set out(pointfmts_dec) $pointfmts_dec
    set out(sigalgs_hex)   $sigalgs_hex
    return [array get out]
}

# ---------------------------------------------------------------------------
# proc: _COMPUTE_JA3
#
# JA3 = MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats )
# Each list is decimal, '-'-joined, GREASE already removed, original order
# preserved (JA3 does not sort). The five fields are ','-joined.
# ---------------------------------------------------------------------------
proc _COMPUTE_JA3 { hello_list } {
    array set hello $hello_list
    set parts [list]
    foreach h $hello(ciphers_hex) { lappend parts [scan $h %x] }
    set ciphers [join $parts "-"]

    set parts [list]
    foreach h $hello(exts_hex) { lappend parts [scan $h %x] }
    set exts [join $parts "-"]

    set curves [join $hello(curves_dec) "-"]
    set fmts   [join $hello(pointfmts_dec) "-"]
    set ver    [scan $hello(ver_hex) %x]

    set ja3_str "${ver},${ciphers},${exts},${curves},${fmts}"
    binary scan [md5 $ja3_str] H* out
    return $out
}

# ---------------------------------------------------------------------------
# proc: _COMPUTE_JA4
#
# JA4 = JA4_a _ JA4_b _ JA4_c, per the FoxIO JA4 spec (BSD-3 core method).
#   a: transport + TLS version + SNI(d/i) + cipher count + ext count + ALPN 2-char
#   b: sha256(comma-joined hex ciphers, sorted) truncated to 12
#   c: sha256(sorted hex exts excluding 0000/0010 _ original-order sig algs)[:12]
# ---------------------------------------------------------------------------
proc _COMPUTE_JA4 { hello_list } {
    array set hello $hello_list
    set cl $hello(ciphers_hex)
    set el $hello(exts_hex)
    set sal $hello(sigalgs_hex)

    set cc [llength $cl]
    if { $cc > 99 } { set cc 99 }
    set ec [llength $el]
    if { $ec > 99 } { set ec 99 }
    if { $hello(has_sni) } { set sni "d" } else { set sni "i" }

    set ja4_a "$hello(tprt)$hello(ver_2char)${sni}[format %02d $cc][format %02d $ec]$hello(alpn_2char)"

    set cipher_str [join [lsort $cl] ","]
    if { $cipher_str eq "" } {
        set ja4_b "000000000000"
    } else {
        binary scan [sha256 $cipher_str] H* ch
        set ja4_b [string range $ch 0 11]
    }

    set ext_for_hash [list]
    foreach e $el {
        if { $e ne "0000" && $e ne "0010" } { lappend ext_for_hash $e }
    }
    set ext_str  [join [lsort $ext_for_hash] ","]
    set siga_str [join $sal ","]
    if { $siga_str ne "" } {
        set hash_input "${ext_str}_${siga_str}"
    } else {
        set hash_input $ext_str
    }
    if { $ext_str eq "" && $siga_str eq "" } {
        set ja4_c "000000000000"
    } else {
        binary scan [sha256 $hash_input] H* eh
        set ja4_c [string range $eh 0 11]
    }

    return "${ja4_a}_${ja4_b}_${ja4_c}"
}

# ---------------------------------------------------------------------------
# proc: ENQUEUE_TRAFFIC
#
# Hand one event to the shared event buffer in MIDEYE_SHIELD_COMMON, sized by
# the traffic_* settings and held in this iRule's own subtable. The POST is
# left to CLIENT_CLOSED below; see _ENQUEUE_EVENT_DEFERRED there.
# ---------------------------------------------------------------------------
proc ENQUEUE_TRAFFIC { event_json } {
    call /__partition__/MIDEYE_SHIELD_COMMON::_ENQUEUE_EVENT_DEFERRED "MIDEYE_SHIELD_TRAFFIC" $event_json \
        $static::MIDEYE_SHIELD_traffic_batch_size \
        $static::MIDEYE_SHIELD_traffic_flush_interval \
        $static::MIDEYE_SHIELD_traffic_max_buffer
}

# ===========================================================================
# E V E N T S
# ===========================================================================

when CLIENT_ACCEPTED {
    # Reset per-connection fingerprint state. When reporting is enabled, start
    # collecting so CLIENT_DATA sees the raw ClientHello.
    set ms_traffic_ch_pending 0
    unset -nocomplain ms_traffic_ja3 ms_traffic_ja4 ms_traffic_tls_version \
        ms_traffic_alpn ms_traffic_reported

    # Anything but 1 stays silent, an unsubstituted placeholder included. The
    # block reporting in COMMON deliberately fails the other way; reporting on
    # traffic nobody asked to report on is the worse failure here.
    if { $static::MIDEYE_SHIELD_traffic_enabled == 1 } {
        set ms_traffic_ch_pending 1
        TCP::collect
    }
}

when CLIENT_DATA {
    # Only act on the collection this iRule started.
    if { ![info exists ms_traffic_ch_pending] || $ms_traffic_ch_pending != 1 } {
        return
    }

    set payload [TCP::payload]
    set plen    [TCP::payload length]

    if { $plen < 5 } {
        TCP::collect 5
        return
    }

    binary scan $payload cH4S content_type proto_ver rlen
    set content_type [expr { $content_type & 0xff }]
    set rlen         [expr { $rlen & 0xffff }]
    set total_needed [expr { $rlen + 5 }]

    if { $content_type != 0x16
         || $total_needed > $static::MIDEYE_SHIELD_traffic_max_record
         || $total_needed < 44 } {
        set ms_traffic_ch_pending 0
        TCP::release
        return
    }

    if { $plen < $total_needed } {
        TCP::collect $total_needed
        return
    }

    set ms_traffic_ch_pending 0

    if { ![catch { set hello [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_PARSE_CLIENTHELLO $payload $total_needed] }] && $hello ne "" } {
        set ms_traffic_ja3         [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_COMPUTE_JA3 $hello]
        set ms_traffic_ja4         [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_COMPUTE_JA4 $hello]
        array set hello_fields $hello
        set ms_traffic_tls_version [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_MAP_TLS_VERSION $hello_fields(ver_2char)]
        set ms_traffic_alpn        $hello_fields(alpn_proto)
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "traffic-intel: fingerprint src=[IP::client_addr] ja3=$ms_traffic_ja3 ja4=$ms_traffic_ja4 alpn=$ms_traffic_alpn"
    }

    TCP::release
}

when HTTP_REQUEST {
    if { $static::MIDEYE_SHIELD_traffic_enabled != 1 } {
        return
    }

    if { [catch {
        # Reaching a request with the collect still outstanding means another
        # iRule released it before CLIENT_DATA could parse the handshake. The
        # cause is ordering - list this iRule after MIDEYE_SHIELD_CONNECTION.
        # Said once per connection, because the symptom is otherwise silence.
        if { [info exists ms_traffic_ch_pending] && $ms_traffic_ch_pending == 1 } {
            set ms_traffic_ch_pending 0
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "traffic-intel: no ClientHello captured; list MIDEYE_SHIELD_TRAFFIC after MIDEYE_SHIELD_CONNECTION on this Virtual Server"
        }

        set ip [lindex [split [IP::client_addr] "%"] 0]
        set ts [clock format [clock seconds] -format {%Y-%m-%dT%H:%M:%S%z}]

        # The handshake happens once, so the fingerprint and the header ordering
        # are the same for every later request and are reported only on the
        # first. Those carry the JA4 as the key back to it.
        set full [expr { ![info exists ms_traffic_reported] }]

        # --- tlsContext (only when a TLS fingerprint was captured) ---
        set tls ""
        if { [info exists ms_traffic_ja3] || [info exists ms_traffic_ja4] } {
            set tp [list]
            if { [info exists ms_traffic_ja4] && $ms_traffic_ja4 ne "" } {
                lappend tp "\"ja4\":\"$ms_traffic_ja4\""
            }
            if { $full } {
                if { [info exists ms_traffic_tls_version] && $ms_traffic_tls_version ne "" } {
                    lappend tp "\"version\":\"$ms_traffic_tls_version\""
                }
                if { [info exists ms_traffic_ja3] && $ms_traffic_ja3 ne "" } {
                    lappend tp "\"ja3\":\"$ms_traffic_ja3\""
                }
                if { [info exists ms_traffic_alpn] && $ms_traffic_alpn ne "" } {
                    set ae [call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE [string range $ms_traffic_alpn 0 15]]
                    lappend tp "\"alpn\":\"$ae\""
                }
                # Own catch: SSL::cipher throws on a plaintext Virtual Server
                # and must not void the rest of the event.
                if { ![catch { set ms_traffic_cs [SSL::cipher name] }] && $ms_traffic_cs ne "" } {
                    set ce [call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE [string range $ms_traffic_cs 0 199]]
                    lappend tp "\"cipherSuite\":\"$ce\""
                }
            }
            if { [llength $tp] > 0 } {
                set tls "\"tlsContext\":\{[join $tp ,]\}"
            }
        }

        # --- httpContext (method, User-Agent, ordered header names, version) ---
        set hp [list]
        set method [HTTP::method]
        if { $method ne "" } {
            set me [call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE [string range $method 0 15]]
            lappend hp "\"method\":\"$me\""
        }
        if { $full && [HTTP::header exists "User-Agent"] } {
            set ua [string range [HTTP::header value "User-Agent"] 0 4095]
            if { $ua ne "" } {
                set ue [call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE $ua]
                lappend hp "\"userAgent\":\{\"rawValue\":\"$ue\"\}"
            }
        }
        if { $full } {
            set hitems [list]
            set hcount 0
            set hbytes 0
            foreach name [HTTP::header names] {
                # Two bounds: the count, and the bytes those names cost once
                # escaped. Truncating keeps the leading order, which is where
                # the fingerprint lives.
                if { $hcount >= 100 || $hbytes >= $static::MIDEYE_SHIELD_traffic_max_headers } { break }
                if { $name eq "" } { continue }
                if { [lsearch -exact $static::MIDEYE_SHIELD_traffic_forbidden_headers [string tolower $name]] >= 0 } { continue }
                set ne [call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE [string range $name 0 255]]
                set hval ""
                set cap [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_HEADER_VALUE_CAP $name]
                if { $cap ne "" } {
                    set hval [call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE \
                        [string range [HTTP::header value $name] 0 $cap]]
                }
                set hitem "\{\"name\":\"$ne\",\"value\":\"$hval\"\}"
                lappend hitems $hitem
                incr hbytes [string length $hitem]
                incr hcount
            }
            if { [llength $hitems] > 0 } {
                lappend hp "\"headers\":\[[join $hitems ,]\]"
            }
            set hv [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_MAP_HTTP_VERSION [HTTP::version]]
            if { $hv ne "" } {
                lappend hp "\"httpVersion\":\"$hv\""
            }
        }
        set http ""
        if { [llength $hp] > 0 } {
            set http "\"httpContext\":\{[join $hp ,]\}"
        }

        # --- destination (host as application, path as resource; no query) ---
        set dp [list]
        set host [HTTP::host]
        if { $host ne "" } {
            set he [call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE [string range $host 0 255]]
            lappend dp "\"application\":\{\"id\":\"$he\"\}"
        }
        set path [HTTP::path]
        if { $path ne "" } {
            set pe [call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE [string range $path 0 1023]]
            lappend dp "\"resource\":\{\"id\":\"$pe\"\}"
        }
        set dest ""
        if { [llength $dp] > 0 } {
            set dest "\"destination\":\{[join $dp ,]\}"
        }

        # --- source (which sensor observed this) ---
        # The type is fixed, not a setting: only the honeypot and lab types opt
        # traffic into Shield-side raw request capture, and a BIG-IP is neither.
        set src ""
        set sid $static::MIDEYE_SHIELD_traffic_sensor_id
        if { $sid eq "" } {
            set sid $static::MIDEYE_SHIELD_traffic_device_hostname
        }
        if { $sid eq "" } {
            # The deploy-time lookup is guarded and can come up empty; without
            # this a default deployment ships every event unattributed.
            catch { set sid [info hostname] }
        }
        if { $sid ne "" } {
            set sie [call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE [string range $sid 0 255]]
            set src "\"source\":\{\"id\":\"$sie\",\"type\":\"enforcement_point\"\}"
        }

        # The Shield API requires at least one context, and source is not one:
        # identity without an observation is not an event. A guard rather than
        # a return, which inside catch would trip the error branch below.
        if { $tls ne "" || $http ne "" || $dest ne "" } {
            set ep [list]
            lappend ep "\"ipAddress\":\"$ip\""
            lappend ep "\"observedAt\":\"$ts\""
            if { $tls  ne "" } { lappend ep $tls }
            if { $http ne "" } { lappend ep $http }
            if { $dest ne "" } { lappend ep $dest }
            if { $src  ne "" } { lappend ep $src }
            set event "\{[join $ep ,]\}"

            # The bound that makes a batch a known multiple of a known number.
            # Over it the event is dropped rather than trimmed: the connection
            # falls back to the slim shape, which still carries the JA4, so the
            # client stays identified and nobody gets to pick the event size.
            if { [string length $event] <= $static::MIDEYE_SHIELD_traffic_max_event } {
                call /__partition__/MIDEYE_SHIELD_TRAFFIC::ENQUEUE_TRAFFIC $event
            } else {
                call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "traffic-intel: oversized event dropped ([string length $event] bytes)"
            }

            # Reached only once the event was built, so a throw above still
            # leaves the next request to try the full shape again. A drop marks
            # it too - retrying the same oversized shape every request is what
            # the bound exists to prevent.
            set ms_traffic_reported 1
        }
    } err] } {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "traffic-intel: HTTP_REQUEST capture failed -> '$err'"
    }
}

when CLIENT_CLOSED {
    if { $static::MIDEYE_SHIELD_traffic_enabled != 1 } {
        return
    }

    # Where the batch is POSTed: the sideband is synchronous, and here nothing
    # is waiting. Every closing connection checks, which drains the last partial
    # batch once traffic goes quiet. Nothing connection-scoped is read.
    if { [catch {
        call /__partition__/MIDEYE_SHIELD_COMMON::_FLUSH_IF_DUE "MIDEYE_SHIELD_TRAFFIC" \
            $static::MIDEYE_SHIELD_traffic_batch_size \
            $static::MIDEYE_SHIELD_traffic_flush_interval \
            $static::MIDEYE_SHIELD_traffic_max_buffer
    } err] } {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "traffic-intel: deferred flush failed -> '$err'"
    }
}
