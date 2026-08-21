# JA4 against FoxIO's published vector, JA3 against its own recorded output,
# and the ClientHello parser against the shapes that only turn up in hostile
# traffic.
source [file join [file dirname [info script]] fp_harness.tcl]

# md5 stub sanity against a known vector
binary scan [md5 "abc"] H* md5abc
assert {$md5abc eq "900150983cd24fb0d6963f7d28e17f72"} "md5 stub known vector"
binary scan [sha256 "abc"] H* sha256abc
assert {[string range $sha256abc 0 11] eq "ba7816bf8f01"} "sha256 stub known vector"

set hello [corpus_base]
set hello_list [_PARSE_CLIENTHELLO $hello [string length $hello]]
assert {$hello_list ne ""} "base hello parses"
array set h $hello_list

assert {[llength $h(ciphers_hex)] == 4}  "GREASE cipher stripped (4 of 5 kept)"
assert {$h(has_sni) == 1}                "SNI detected"
assert {$h(ver_2char) eq "13"}           "supported_versions max wins (TLS 1.3)"
assert {$h(alpn_2char) eq "h2"}          "ALPN 2char = first+last char of first proto"
assert {$h(alpn_proto) eq "h2"}          "ALPN first protocol captured"
assert {[llength $h(exts_hex)] == 8}     "8 extensions, none GREASE in base"
assert {[llength $h(curves_dec)] == 3}   "3 curves"
assert {[llength $h(sigalgs_hex)] == 2}  "2 sigalgs"

set ja3 [_COMPUTE_JA3 $hello_list]
assert {[string length $ja3] == 32 && [string is xdigit $ja3]} "JA3 is 32 hex chars"

set ja4 [_COMPUTE_JA4 $hello_list]
assert {[string range $ja4 0 9] eq "t13d0408h2"} "ja4_a: tls1.3, sni, 4 ciphers, 8 exts, alpn h2"
assert {[string length $ja4] == 36} "JA4 length a(10)+_+b(12)+_+c(12)"

# determinism of the full pipeline
set hello2 [corpus_base]
set hl2 [_PARSE_CLIENTHELLO $hello2 [string length $hello2]]
assert {[_COMPUTE_JA4 $hl2] eq $ja4} "JA4 deterministic"

# --- the reference hello ----------------------------------------------------
# corpus_reference rebuilds the hello behind FoxIO's canonical JA4 example, so
# the JA4 below is an external value rather than our own output: it catches a
# change that still hashes plausibly, like SNI reaching the JA4_c digest.
#   t13d1516h2_8daaf6152771_e5627efa2ab1
#   github.com/FoxIO-LLC/ja4, README.md and technical_details/JA4.md
set ref [corpus_reference]
set ref_list [_PARSE_CLIENTHELLO $ref [string length $ref]]
assert {$ref_list ne ""} "reference hello parses"

assert {[_COMPUTE_JA4 $ref_list] eq "t13d1516h2_8daaf6152771_e5627efa2ab1"} \
    "JA4 matches FoxIO's published vector"

# No published JA3 exists for that hello, so this is our own output, recorded.
# It cannot show the JA3 method was read right, only that it has not moved.
assert {[_COMPUTE_JA3 $ref_list] eq "cd08e31494f9531f560d64c695473da9"} \
    "JA3 for the reference hello is unchanged"

# JA3 keys on the legacy client_version, JA4 on supported_versions, so a TLS
# 1.0 legacy version must move the JA3 and leave the JA4 alone. What is being
# pinned is that the two differ, not the JA3 digest itself.
set old [corpus_reference 0x0301]
set old_list [_PARSE_CLIENTHELLO $old [string length $old]]
assert {[_COMPUTE_JA3 $old_list] eq "4aac30c66668d803543f7ccadf41deb7"} \
    "JA3 follows the legacy client_version"
assert {[_COMPUTE_JA4 $old_list] eq "t13d1516h2_8daaf6152771_e5627efa2ab1"} \
    "JA4 ignores the legacy client_version"

# --- vectors inside extensions ----------------------------------------------
proc parse_exts {extlist} {
    set hello [build_hello [base_ciphers] $extlist]
    return [_PARSE_CLIENTHELLO $hello [string length $hello]]
}

# GREASE appears inside supported_groups, sig-algs and supported_versions too,
# not only in the cipher and extension lists.
array set g [parse_exts [list [ext_sni] \
    [mkext 0x000a "[be16 8][be16 0x0a0a][be16 0x001d][be16 0x1a1a][be16 0x0017]"] \
    [mkext 0x000d "[be16 6][be16 0x0a0a][be16 0x0403][be16 0x0804]"] \
    [mkext 0x002b "[be8 6][be16 0x0a0a][be16 0x0304][be16 0x0303]"]]]
assert {$g(curves_dec) eq "29 23"}      "GREASE stripped from supported_groups"
assert {$g(sigalgs_hex) eq "0403 0804"} "GREASE stripped from signature algorithms"
assert {$g(ver_2char) eq "13"}          "GREASE ignored when picking the highest version"

# A vector whose length runs past its own extension is dropped, rather than
# read on into whatever follows it.
array set o [parse_exts [list [ext_sni] \
    [mkext 0x000a "[be16 100][be16 0x001d]"] \
    [mkext 0x000b "[be8 100][be8 0]"] [ext_sv]]]
assert {$o(curves_dec) eq ""}    "over-long supported_groups vector is ignored"
assert {$o(pointfmts_dec) eq ""} "over-long point-formats vector is ignored"

# A separate bound from the one above: the length prefix is read before any
# entry, so it needs its own check or the read runs into the next extension.
array set sh [parse_exts [list [ext_sni] \
    [mkext 0x000a [be8 5]] [mkext 0x000b ""] [ext_sv]]]
assert {$sh(curves_dec) eq ""}    "supported_groups too short for its length prefix is ignored"
assert {$sh(pointfmts_dec) eq ""} "point-formats too short for its length prefix is ignored"

# The same shape as the last extension: the prefix runs past the record, the
# read itself fails leaving the length unset, and nothing downstream can catch
# it. The bounds test has to happen first.
set tail [build_hello [base_ciphers] [list [ext_sni] [ext_sv] [mkext 0x000a [be8 5]]]]
set tail_list ""
set threw [catch { set tail_list [_PARSE_CLIENTHELLO $tail [string length $tail]] }]
assert {$threw == 0} "a length prefix running past the record does not throw"
array set tl [concat {curves_dec {}} $tail_list]
assert {$tl(curves_dec) eq ""} "a length prefix running past the record yields no curves"

# A GREASE extension TYPE is stripped just like a GREASE cipher. The published
# reference hello happens to carry none, so nothing else pins this.
array set ge [parse_exts [list [mkext 0x2a2a ""] [ext_sni] [ext_curves] [ext_sv]]]
assert {[llength $ge(exts_hex)] == 3}                 "GREASE extension type is stripped"
assert {[lsearch -exact $ge(exts_hex) "2a2a"] < 0}    "GREASE extension type never reaches the list"

# --- JA4 ALPN field ---------------------------------------------------------
# First and last character when both are alphanumeric, otherwise the first and
# last nibble of the hex. ALPN is attacker-controlled, so the fallback matters.
proc alpn_2char {proto} {
    set entry "[be8 [string length $proto]]$proto"
    set hello [build_hello [base_ciphers] [list [ext_sni] [ext_curves] \
        [mkext 0x0010 "[be16 [string length $entry]]$entry"] [ext_sv]]]
    array set h [_PARSE_CLIENTHELLO $hello [string length $hello]]
    return $h(alpn_2char)
}
assert {[alpn_2char "h2"] eq "h2"}       "ALPN h2 uses its own characters"
assert {[alpn_2char "a"] eq "aa"}        "single-character ALPN doubles"
assert {[alpn_2char "-x-"] eq "2d"}      "non-alphanumeric ALPN falls back to hex"
assert {[alpn_2char "\xff\x01"] eq "f1"} "high-byte ALPN falls back to hex"
assert {[alpn_2char ""] eq "00"}         "absent ALPN is 00"

# --- malformed input is rejected, not fingerprinted -------------------------
# A hello whose handshake does not fit its record (fragmented across records,
# or a lying length) must return "" rather than a confident wrong answer.
set truncated [string range $ref 0 [expr { [string length $ref] - 40 }]]
assert {[_PARSE_CLIENTHELLO $truncated [string length $truncated]] eq ""} \
    "truncated ClientHello is rejected"

# A record carrying only the first part of its handshake: the length at offsets
# 6-8 promises more than the record delivers, while everything inside it still
# parses cleanly. Without the length check this is a stable, wrong answer.
binary scan $ref @6H6 hs_hex
set split_rec [string replace $ref 6 8 \
    [binary format H6 [format %06x [expr { [scan $hs_hex %x] + 100 }]]]]
assert {[_PARSE_CLIENTHELLO $split_rec [string length $split_rec]] eq ""} \
    "ClientHello split across records is rejected"

# An extension whose length runs past the extensions block contradicts those
# same length fields. Rejecting the whole parse is what matters here: the
# extensions read before it are a complete-looking list, and stopping there
# yields a stable, confident, wrong JA4.
set bad_ext "[be16 0x000a][be16 200][be16 0x001d]"
set overrun [build_hello [base_ciphers] [list [ext_sni] $bad_ext [ext_sv]]]
assert {[_PARSE_CLIENTHELLO $overrun [string length $overrun]] eq ""} \
    "an extension running past the block rejects the whole hello"

# RFC 8446 allows each extension type once. A repeat would have its vector read
# twice and its type counted twice, fingerprinting as something no client sends.
set dup [build_hello [base_ciphers] [list [ext_sni] [ext_curves] [ext_curves] [ext_sv]]]
assert {[_PARSE_CLIENTHELLO $dup [string length $dup]] eq ""} \
    "a repeated extension type rejects the whole hello"

finish
