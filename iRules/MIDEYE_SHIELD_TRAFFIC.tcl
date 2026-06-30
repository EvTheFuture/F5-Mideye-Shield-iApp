# =============================================================================
# iRule   : MIDEYE_SHIELD_TRAFFIC
# Version : 0.1.0
# Author  : Mideye
# Date    : 2026-06-30
#
# Purpose
# -------
# Report per-connection CLIENT FINGERPRINTS for ALL traffic that reaches a
# protected Virtual Server - not just authentication attempts. For every
# connection it computes the TLS-stack fingerprints (JA3 + JA4) from the raw
# ClientHello and, on the first HTTP request, captures the HTTP engine's
# identity (ordered header NAMES, User-Agent, HTTP version) and the
# destination (host + path). Events are buffered per-TMM and flushed in
# batches to the Shield ingest API over the existing HSSR sideband.
#
# This is a context-only producer: it never sends an `authentication` block,
# so the Shield API routes these events to traffic-intel storage and they
# never create scored IP documents. The existing auth path (REPORT_AUTH_RESULT
# in MIDEYE_SHIELD_COMMON) is untouched and keeps its own per-event sideband.
#
# Attach this iRule to any Virtual Server you want fingerprinted. It is inert
# until "Report client fingerprints for all traffic" is enabled in the iApp.
# When co-resident with MIDEYE_SHIELD_CONNECTION, list this iRule AFTER it so
# the connection-validation event completes first; a ClientHello parse miss is
# fail-open (the fingerprint is simply dropped, the connection is untouched).
#
# Privacy
# -------
# Only header NAMES are sent (values are dropped at the BIG-IP); the
# Shield API stores a hash of the name order, never the values. The URL query
# string is dropped (path only). JA3/JA4 are already one-way hashes.
#
# Provenance / licensing
# ----------------------
# The ClientHello byte parsing is adapted from f5devcentral/f5-ja4
# (Copyright (c) 2024 FoxIO) - JA4 TLS Client Fingerprinting, BSD 3-Clause.
# JA3 is Salesforce's method (BSD 3-Clause). Both core JA4 and JA3 are
# BSD-3-licensed. JA4+ variants (e.g. JA4H) are FoxIO License 1.1 and are NOT
# implemented here.
#
# Dependencies - iRules (call targets)
# ------------------------------------
#   /__partition__/MIDEYE_SHIELD_COMMON   - shared library: _GET_VALID_TOKEN,
#       _BUILD_HSSR_ARGS, LOG_*. Settings (api_base_url, api_timeout, and the
#       traffic_* knobs) live in its RULE_INIT.
#   __hssr_irule__                        - HSSR sideband requester (POST).
#
# Dependencies - Session Table (subtable "MIDEYE_SHIELD_TRAFFIC")
# --------------------------------------------------------------
#   seq         - monotonic event sequence number (per TMM)
#   cursor      - highest sequence number already flushed
#   evt_<n>     - buffered event JSON for sequence n (self-expiring)
#   last_flush  - epoch seconds of the last flush
#   flush_lock  - binary lock: present means a flush is in progress
#   dropped     - counter: events dropped because the buffer was full
# =============================================================================

when RULE_INIT {
    # Internal parsing/buffer constants (not user-configurable, so they are not
    # in the iApp settings - they live with the code that uses them). The
    # user-facing traffic_* settings are declared in MIDEYE_SHIELD_COMMON's
    # RULE_INIT so the iApp generator can cross-check them against the form.
    set static::MIDEYE_SHIELD_traffic_max_record 17408
    set static::MIDEYE_SHIELD_traffic_max_iter   256
    set static::MIDEYE_SHIELD_traffic_event_ttl  120
    set static::MIDEYE_SHIELD_traffic_forbidden_headers "authorization cookie set-cookie x-api-key x-auth-token proxy-authorization x-csrf-token x-xsrf-token"
}

# ===========================================================================
# P R I V A T E   P R O C E D U R E S
# ===========================================================================

# ---------------------------------------------------------------------------
# proc: _JSON_ESCAPE
#
# Escape a string for inclusion in a JSON double-quoted value. Backslash must
# be mapped first so it does not double-escape the others.
# ---------------------------------------------------------------------------
proc _JSON_ESCAPE { s } {
    return [string map [list \\ \\\\ \" \\\" \n \\n \r \\r \t \\t] $s]
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
# proc: _PARSE_CLIENTHELLO
#
# Parse a complete TLS ClientHello record (already fully collected, length
# bounded by total_needed) into a dict of the fields JA3 and JA4 need. Returns
# "" if the payload is not a ClientHello or is malformed. GREASE values
# (RFC 8701) are stripped from ciphers, extensions, curves and sig-algs.
#
# Adapted from f5devcentral/f5-ja4 (BSD-3); extended to also collect the
# decimal cipher/extension/curve/point-format lists JA3 requires.
# ---------------------------------------------------------------------------
proc _PARSE_CLIENTHELLO { payload total_needed } {
    binary scan $payload @5c handshake_type
    set handshake_type [expr { $handshake_type & 0xff }]
    if { $handshake_type != 0x01 } {
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
    if { $cs_length < 0 || ($cs_length % 2) != 0 || $off + $cs_length > $total_needed } {
        return ""
    }
    set cs_end [expr { $off + $cs_length }]
    set ciphers_hex [list]
    set cs_iter 0
    while { $off < $cs_end } {
        if { [incr cs_iter] > $max_iter } { break }
        unset -nocomplain cs_int cs_hex
        binary scan $payload @${off}SH4 cs_int cs_hex
        if { ![info exists cs_hex] || [string length $cs_hex] != 4 } { break }
        set cs_int [expr { $cs_int & 0xffff }]
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
    set ja4_tprt      "t"
    set ver_2char_src $ver_hex
    set exts_hex      [list]
    set curves_dec    [list]
    set pointfmts_dec [list]
    set sigalgs_hex   [list]

    if { $off + 2 <= $total_needed } {
        binary scan $payload @${off}S ext_total_len
        set ext_total_len [expr { $ext_total_len & 0xffff }]
        incr off 2
        if { $ext_total_len >= 0 && $off + $ext_total_len <= $total_needed } {
            set ext_end [expr { $off + $ext_total_len }]
            set ext_iter 0
            while { $off + 4 <= $ext_end } {
                if { [incr ext_iter] > $max_iter } { break }
                unset -nocomplain et_int et_hex
                binary scan $payload @${off}SH4 et_int et_hex
                if { ![info exists et_hex] || [string length $et_hex] != 4 } { break }
                set et_int [expr { $et_int & 0xffff }]
                incr off 2
                binary scan $payload @${off}S et_len
                set et_len [expr { $et_len & 0xffff }]
                incr off 2
                set data_start $off
                if { $et_len < 0 || $data_start + $et_len > $ext_end } { break }
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
                        if { $et_len >= 2 } {
                            binary scan $payload @${data_start}S grp_len
                            set grp_len [expr { $grp_len & 0xffff }]
                            if { $grp_len >= 0 && ($grp_len % 2) == 0 && $grp_len + 2 <= $et_len } {
                                set g_off [expr { $data_start + 2 }]
                                set g_end [expr { $g_off + $grp_len }]
                                set g_iter 0
                                while { $g_off + 2 <= $g_end } {
                                    if { [incr g_iter] > $max_iter } { break }
                                    unset -nocomplain g_int
                                    binary scan $payload @${g_off}S g_int
                                    set g_int [expr { $g_int & 0xffff }]
                                    incr g_off 2
                                    if { ($g_int & 0x0f0f) == 0x0a0a && (($g_int >> 8) & 0xff) == ($g_int & 0xff) } { continue }
                                    lappend curves_dec $g_int
                                }
                            }
                        }
                    }
                    "000b" {
                        if { $et_len >= 1 } {
                            binary scan $payload @${data_start}c pf_len
                            set pf_len [expr { $pf_len & 0xff }]
                            if { $pf_len >= 0 && $pf_len + 1 <= $et_len } {
                                set p_off [expr { $data_start + 1 }]
                                set p_end [expr { $p_off + $pf_len }]
                                set p_iter 0
                                while { $p_off < $p_end } {
                                    if { [incr p_iter] > $max_iter } { break }
                                    unset -nocomplain pf_int
                                    binary scan $payload @${p_off}c pf_int
                                    set pf_int [expr { $pf_int & 0xff }]
                                    incr p_off 1
                                    lappend pointfmts_dec $pf_int
                                }
                            }
                        }
                    }
                    "000d" {
                        if { $et_len >= 2 } {
                            binary scan $payload @${data_start}S sa_len
                            set sa_len [expr { $sa_len & 0xffff }]
                            if { $sa_len >= 0 && ($sa_len % 2) == 0 && $sa_len + 2 <= $et_len } {
                                set sa_off [expr { $data_start + 2 }]
                                set sa_end [expr { $sa_off + $sa_len }]
                                set sa_iter 0
                                while { $sa_off + 2 <= $sa_end } {
                                    if { [incr sa_iter] > $max_iter } { break }
                                    unset -nocomplain sa_int sa_hex
                                    binary scan $payload @${sa_off}SH4 sa_int sa_hex
                                    if { ![info exists sa_hex] || [string length $sa_hex] != 4 } { break }
                                    set sa_int [expr { $sa_int & 0xffff }]
                                    incr sa_off 2
                                    if { ($sa_int & 0x0f0f) == 0x0a0a && (($sa_int >> 8) & 0xff) == ($sa_int & 0xff) } { continue }
                                    lappend sigalgs_hex $sa_hex
                                }
                            }
                        }
                    }
                    "0010" {
                        if { $et_len >= 4 } {
                            binary scan $payload @[expr {$data_start + 2}]c alpn_str_len
                            set alpn_str_len [expr { $alpn_str_len & 0xff }]
                            if { $alpn_str_len > 0 && $alpn_str_len + 3 <= $et_len } {
                                binary scan $payload @[expr {$data_start + 3}]a${alpn_str_len} alpn_proto
                                binary scan $payload @[expr {$data_start + 3}]H[expr {$alpn_str_len * 2}] alpn_hex
                                if { [string length $alpn_proto] >= 1 } {
                                    set fb [scan [string index $alpn_proto 0] %c]
                                    set lb [scan [string index $alpn_proto end] %c]
                                    set first_ok [expr { ($fb >= 0x30 && $fb <= 0x39) || ($fb >= 0x41 && $fb <= 0x5A) || ($fb >= 0x61 && $fb <= 0x7A) }]
                                    set last_ok  [expr { ($lb >= 0x30 && $lb <= 0x39) || ($lb >= 0x41 && $lb <= 0x5A) || ($lb >= 0x61 && $lb <= 0x7A) }]
                                    if { $first_ok && $last_ok } {
                                        set alpn_2char "[string index $alpn_proto 0][string index $alpn_proto end]"
                                    } else {
                                        set alpn_2char "[string index $alpn_hex 0][string index $alpn_hex end]"
                                    }
                                }
                            }
                        }
                    }
                    "0027" {
                        set ja4_tprt "q"
                    }
                    "002b" {
                        if { $et_len >= 1 } {
                            binary scan $payload @${data_start}c sv_len
                            set sv_len [expr { $sv_len & 0xff }]
                            if { $sv_len >= 0 && ($sv_len % 2) == 0 && $sv_len + 1 <= $et_len } {
                                set sv_off [expr { $data_start + 1 }]
                                set sv_end [expr { $sv_off + $sv_len }]
                                set sv_list [list]
                                set sv_iter 0
                                while { $sv_off + 2 <= $sv_end } {
                                    if { [incr sv_iter] > $max_iter } { break }
                                    unset -nocomplain sv_int sv_hex
                                    binary scan $payload @${sv_off}SH4 sv_int sv_hex
                                    if { ![info exists sv_hex] || [string length $sv_hex] != 4 } { break }
                                    set sv_int [expr { $sv_int & 0xffff }]
                                    incr sv_off 2
                                    if { ($sv_int & 0x0f0f) == 0x0a0a && (($sv_int >> 8) & 0xff) == ($sv_int & 0xff) } { continue }
                                    lappend sv_list $sv_hex
                                }
                                set sv_list [lsort $sv_list]
                                if { [llength $sv_list] > 0 } {
                                    set ver_2char_src [lindex $sv_list end]
                                }
                            }
                        }
                    }
                }
                set off [expr { $data_start + $et_len }]
            }
        }
    }

    switch $ver_2char_src {
        "0304"  { set ver_2char "13" }
        "0303"  { set ver_2char "12" }
        "0302"  { set ver_2char "11" }
        "0301"  { set ver_2char "10" }
        "0300"  { set ver_2char "s3" }
        default { set ver_2char "00" }
    }

    return [dict create \
        ver_hex       $ver_hex \
        ver_2char     $ver_2char \
        tprt          $ja4_tprt \
        has_sni       $has_sni \
        alpn_2char    $alpn_2char \
        alpn_proto    $alpn_proto \
        ciphers_hex   $ciphers_hex \
        exts_hex      $exts_hex \
        curves_dec    $curves_dec \
        pointfmts_dec $pointfmts_dec \
        sigalgs_hex   $sigalgs_hex]
}

# ---------------------------------------------------------------------------
# proc: _COMPUTE_JA3
#
# JA3 = MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats )
# Each list is decimal, '-'-joined, GREASE already removed, original order
# preserved (JA3 does not sort). The five fields are ','-joined.
# ---------------------------------------------------------------------------
proc _COMPUTE_JA3 { hello } {
    set parts [list]
    foreach h [dict get $hello ciphers_hex] { lappend parts [scan $h %x] }
    set ciphers [join $parts "-"]

    set parts [list]
    foreach h [dict get $hello exts_hex] { lappend parts [scan $h %x] }
    set exts [join $parts "-"]

    set curves [join [dict get $hello curves_dec] "-"]
    set fmts   [join [dict get $hello pointfmts_dec] "-"]
    set ver    [scan [dict get $hello ver_hex] %x]

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
proc _COMPUTE_JA4 { hello } {
    set cl [dict get $hello ciphers_hex]
    set el [dict get $hello exts_hex]
    set sal [dict get $hello sigalgs_hex]

    set cc [llength $cl]
    if { $cc > 99 } { set cc 99 }
    set ec [llength $el]
    if { $ec > 99 } { set ec 99 }
    set sni [expr { [dict get $hello has_sni] ? "d" : "i" }]

    set ja4_a "[dict get $hello tprt][dict get $hello ver_2char]${sni}[format %02d $cc][format %02d $ec][dict get $hello alpn_2char]"

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
# Append one context-only event (JSON string) to this TMM's buffer. Drops the
# event (fail-open, counted) when the buffer is at capacity. Triggers a flush
# when the buffer reaches the batch size OR the flush interval has elapsed
# since the last flush (the time trigger fires on the next event after T - a
# truly idle buffer self-expires via the per-event TTL).
# ---------------------------------------------------------------------------
proc ENQUEUE_TRAFFIC { event_json } {
    set sub "MIDEYE_SHIELD_TRAFFIC"
    set N      $static::MIDEYE_SHIELD_traffic_batch_size
    set T      $static::MIDEYE_SHIELD_traffic_flush_interval
    set MAXBUF $static::MIDEYE_SHIELD_traffic_max_buffer
    set TTL    $static::MIDEYE_SHIELD_traffic_event_ttl

    set seq [table incr -subtable $sub "seq"]
    if { $seq == 1 } {
        table set -subtable $sub "seq" 1 indefinite indefinite
    }

    set cursor [table lookup -subtable $sub "cursor"]
    if { $cursor eq "" } { set cursor 0 }
    set buffered [expr { $seq - $cursor }]

    if { $buffered > $MAXBUF } {
        table incr -subtable $sub "dropped"
        return
    }

    table set -subtable $sub "evt_$seq" $event_json $TTL $TTL

    set last [table lookup -subtable $sub "last_flush"]
    if { $last eq "" } { set last 0 }

    if { $buffered >= $N || ([clock seconds] - $last) >= $T } {
        call /__partition__/MIDEYE_SHIELD_TRAFFIC::FLUSH_TRAFFIC
    }
}

# ---------------------------------------------------------------------------
# proc: FLUSH_TRAFFIC
#
# Gather up to 1000 buffered events (the Shield API per-request cap) into one
# {"events":[...]} body and POST it once over HSSR. A binary lock serialises
# flushers per TMM. Fire-and-forget: a failed POST drops that batch rather than
# retrying, keeping the buffer bounded (best-effort telemetry, not enforcement).
# ---------------------------------------------------------------------------
proc FLUSH_TRAFFIC {} {
    set sub "MIDEYE_SHIELD_TRAFFIC"
    set TIMEOUT  $static::MIDEYE_SHIELD_api_timeout
    set LOCK_TTL [expr { int($TIMEOUT / 1000) + 5 }]

    if { [table add -subtable $sub "flush_lock" 1 $LOCK_TTL $LOCK_TTL] != 1 } {
        return
    }

    set cursor [table lookup -subtable $sub "cursor"]
    if { $cursor eq "" } { set cursor 0 }
    set seq [table lookup -subtable $sub "seq"]
    if { $seq eq "" } { set seq 0 }

    set end $seq
    if { [expr { $end - $cursor }] > 1000 } {
        set end [expr { $cursor + 1000 }]
    }

    set events [list]
    for { set s [expr { $cursor + 1 }] } { $s <= $end } { incr s } {
        set j [table lookup -subtable $sub "evt_$s"]
        if { $j ne "" } {
            lappend events $j
            table delete -subtable $sub "evt_$s"
        }
    }

    table set -subtable $sub "cursor" $end indefinite indefinite
    table set -subtable $sub "last_flush" [clock seconds] indefinite indefinite

    if { [llength $events] == 0 } {
        table delete -subtable $sub "flush_lock"
        return
    }

    set BODY "\{\"events\":\[[join $events ,]\]\}"

    call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "traffic-intel: flushing [llength $events] event(s) to /ips/events"

    catch {
        set TOKEN [call /__partition__/MIDEYE_SHIELD_COMMON::_GET_VALID_TOKEN]
        if { $TOKEN ne "" } {
            set BASE_URL $static::MIDEYE_SHIELD_api_base_url
            call /__partition__/MIDEYE_SHIELD_COMMON::_BUILD_HSSR_ARGS ARGS "POST" "${BASE_URL}/ips/events"
            lappend ARGS \
                -headers [list "Authorization" "Bearer ${TOKEN}"] \
                -body    $BODY \
                -type    "application/json"
            call __hssr_irule__::http_req $ARGS
        }
    }

    table delete -subtable $sub "flush_lock"
}

# ===========================================================================
# E V E N T S
# ===========================================================================

when CLIENT_ACCEPTED {
    # Reset per-connection fingerprint state. When reporting is enabled, start
    # collecting so CLIENT_DATA sees the raw ClientHello.
    set ms_traffic_ch_pending 0
    unset -nocomplain ms_traffic_ja3 ms_traffic_ja4 ms_traffic_tls_version ms_traffic_alpn

    if { $static::MIDEYE_SHIELD_traffic_enabled == 1 } {
        set ms_traffic_ch_pending 1
        TCP::collect
    }
}

when CLIENT_DATA {
    # Only act on the collection WE started (coexistence with other iRules that
    # may collect on the same VS - never touch their TCP state).
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
        set ms_traffic_tls_version [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_MAP_TLS_VERSION [dict get $hello ver_2char]]
        set ms_traffic_alpn        [dict get $hello alpn_proto]
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "traffic-intel: fingerprint src=[IP::client_addr] ja3=$ms_traffic_ja3 ja4=$ms_traffic_ja4 alpn=$ms_traffic_alpn"
    }

    TCP::release
}

when HTTP_REQUEST {
    if { $static::MIDEYE_SHIELD_traffic_enabled != 1 } {
        return
    }

    if { [catch {
        set ip [lindex [split [IP::client_addr] "%"] 0]
        set ts [clock format [clock seconds] -format {%Y-%m-%dT%H:%M:%S%z}]

        # --- tlsContext (only when a TLS fingerprint was captured) ---
        set tls ""
        if { [info exists ms_traffic_ja3] || [info exists ms_traffic_ja4] } {
            set tp [list]
            if { [info exists ms_traffic_tls_version] && $ms_traffic_tls_version ne "" } {
                lappend tp "\"version\":\"$ms_traffic_tls_version\""
            }
            if { [info exists ms_traffic_ja3] && $ms_traffic_ja3 ne "" } {
                lappend tp "\"ja3\":\"$ms_traffic_ja3\""
            }
            if { [info exists ms_traffic_ja4] && $ms_traffic_ja4 ne "" } {
                lappend tp "\"ja4\":\"$ms_traffic_ja4\""
            }
            if { [info exists ms_traffic_alpn] && $ms_traffic_alpn ne "" } {
                set ae [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_JSON_ESCAPE [string range $ms_traffic_alpn 0 15]]
                lappend tp "\"alpn\":\"$ae\""
            }
            if { [llength $tp] > 0 } {
                set tls "\"tlsContext\":\{[join $tp ,]\}"
            }
        }

        # --- httpContext (User-Agent, ordered header names, HTTP version) ---
        set hp [list]
        if { [HTTP::header exists "User-Agent"] } {
            set ua [string range [HTTP::header value "User-Agent"] 0 4095]
            if { $ua ne "" } {
                set ue [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_JSON_ESCAPE $ua]
                lappend hp "\"userAgent\":\{\"rawValue\":\"$ue\"\}"
            }
        }
        set hitems [list]
        set hcount 0
        foreach name [HTTP::header names] {
            if { $hcount >= 100 } { break }
            if { $name eq "" } { continue }
            if { [lsearch -exact $static::MIDEYE_SHIELD_traffic_forbidden_headers [string tolower $name]] >= 0 } { continue }
            set ne [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_JSON_ESCAPE [string range $name 0 255]]
            lappend hitems "\{\"name\":\"$ne\",\"value\":\"\"\}"
            incr hcount
        }
        if { [llength $hitems] > 0 } {
            lappend hp "\"headers\":\[[join $hitems ,]\]"
        }
        set hv [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_MAP_HTTP_VERSION [HTTP::version]]
        if { $hv ne "" } {
            lappend hp "\"httpVersion\":\"$hv\""
        }
        set http ""
        if { [llength $hp] > 0 } {
            set http "\"httpContext\":\{[join $hp ,]\}"
        }

        # --- destination (host as application, path as resource; no query) ---
        set dp [list]
        set host [HTTP::host]
        if { $host ne "" } {
            set he [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_JSON_ESCAPE [string range $host 0 255]]
            lappend dp "\"application\":\{\"id\":\"$he\"\}"
        }
        set path [HTTP::path]
        if { $path ne "" } {
            set pe [call /__partition__/MIDEYE_SHIELD_TRAFFIC::_JSON_ESCAPE [string range $path 0 1023]]
            lappend dp "\"resource\":\{\"id\":\"$pe\"\}"
        }
        set dest ""
        if { [llength $dp] > 0 } {
            set dest "\"destination\":\{[join $dp ,]\}"
        }

        # The Shield API requires at least one context; only enqueue a real
        # event (guard, not return - a return inside catch is a non-zero
        # completion code and would trip the error branch below).
        if { $tls ne "" || $http ne "" || $dest ne "" } {
            set ep [list]
            lappend ep "\"ipAddress\":\"$ip\""
            lappend ep "\"observedAt\":\"$ts\""
            if { $tls  ne "" } { lappend ep $tls }
            if { $http ne "" } { lappend ep $http }
            if { $dest ne "" } { lappend ep $dest }
            call /__partition__/MIDEYE_SHIELD_TRAFFIC::ENQUEUE_TRAFFIC "\{[join $ep ,]\}"
        }
    } err] } {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "traffic-intel: HTTP_REQUEST capture failed -> '$err'"
    }
}
