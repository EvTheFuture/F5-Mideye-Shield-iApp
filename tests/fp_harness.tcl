# =============================================================================
# fp_harness.tcl - load MIDEYE_SHIELD_TRAFFIC.tcl procs into plain tclsh.
#
# TMM runs a Tcl 8.4 interpreter with no dict command. Remove it here so any
# accidental use in the sourced procs fails loudly instead of passing on a
# desktop 8.6. The md5 and sha256 iRule commands are emulated with openssl.
# =============================================================================
rename dict ""

# Run the iRule's own RULE_INIT so the statics under test come from the source
# of truth rather than a copy here that drifts. Other event bodies are kept so
# a test can drive them against stubbed iRule commands.
array set ::EVENT_BODY {}
proc when {event body} {
    if { $event eq "RULE_INIT" } { uplevel #0 $body }
    set ::EVENT_BODY($event) $body
}

proc md5 {s}    { return [binary format H* [lindex [exec openssl dgst -md5    -r << $s] 0]] }
proc sha256 {s} { return [binary format H* [lindex [exec openssl dgst -sha256 -r << $s] 0]] }

namespace eval ::static {}

# In TMM a proc is reached as call /__partition__/RULE::PROC. Here they are
# plain procs, so dispatch on the name after the last colon.
proc call {target args} {
    return [uplevel 1 [linsert $args 0 [lindex [split $target ":"] end]]]
}

# COMMON first: TRAFFIC calls into it, and sourcing the real thing keeps those
# calls from drifting into stub copies.
source [file join [file dirname [info script]] .. iRules MIDEYE_SHIELD_COMMON.tcl]
source [file join [file dirname [info script]] .. iRules MIDEYE_SHIELD_TRAFFIC.tcl]

# A test that replaces one of the sourced procs does so itself, so every stub
# is visible in the test that relies on it.
proc LOG_DEBUG {args} {}

source [file join [file dirname [info script]] assert.tcl]

# --- ClientHello builder ------------------------------------------------------
proc be8  {v} { return [binary format c $v] }
proc be16 {v} { return [binary format S $v] }
proc mkext {type content} { return "[be16 $type][be16 [string length $content]]$content" }

# build_hello: assemble a full TLS record (header + ClientHello handshake).
#   ciphers  - raw cipher_suites chunk (binary, even length)
#   extlist  - ordered list of mkext results
#   rndchar  - the byte repeated 32x as client_random
#   sessid   - raw legacy_session_id (binary, <=32 bytes)
#   legver   - legacy client_version; JA3 keys on this, JA4 does not
proc build_hello {ciphers extlist {rndchar A} {sessid ""} {legver 0x0303}} {
    set exts [join $extlist ""]
    set body [be16 $legver]
    append body [string repeat $rndchar 32]
    append body [be8 [string length $sessid]] $sessid
    append body [be16 [string length $ciphers]] $ciphers
    append body [be8 1] [be8 0]
    append body [be16 [string length $exts]] $exts
    set hs "[be8 1][be8 0][be16 [string length $body]]$body"
    return "[be8 0x16][be16 0x0301][be16 [string length $hs]]$hs"
}

# --- shared corpus pieces -----------------------------------------------------
# Base ciphers: 1 GREASE (0x0a0a) + TLS13 x3 + 1 legacy = JA4 count 04
proc base_ciphers {} { return "[be16 0x0a0a][be16 0x1301][be16 0x1302][be16 0x1303][be16 0xc02f]" }

proc ext_sni {}       { return [mkext 0x0000 "[be16 14][be8 0][be16 11]example.com"] }
proc ext_curves {}    { return [mkext 0x000a "[be16 6][be16 0x001d][be16 0x0017][be16 0x0018]"] }
proc ext_pointfmt {}  { return [mkext 0x000b "[be8 1][be8 0]"] }
proc ext_sigalgs {}   { return [mkext 0x000d "[be16 4][be16 0x0403][be16 0x0804]"] }
proc ext_alpn {}      { return [mkext 0x0010 "[be16 12][be8 2]h2[be8 8]http/1.1"] }
proc ext_sv {}        { return [mkext 0x002b "[be8 4][be16 0x0304][be16 0x0303]"] }
proc ext_keyshare {{fill \x11}} {
    return [mkext 0x0033 "[be16 36][be16 0x001d][be16 32][string repeat $fill 32]"]
}
proc ext_padding {{n 50}} { return [mkext 0x0015 [string repeat \x00 $n]] }

# Base extension order: SNI, curves, pointfmts, sigalgs, ALPN, sv, key_share, padding (8 exts)
proc corpus_base {} {
    return [build_hello [base_ciphers] [list [ext_sni] [ext_curves] [ext_pointfmt] \
        [ext_sigalgs] [ext_alpn] [ext_sv] [ext_keyshare] [ext_padding]]]
}

# The 8 signature algorithms the published reference hello offers.
proc ext_sigalgs_full {} {
    set algs "[be16 0x0403][be16 0x0804][be16 0x0401][be16 0x0503]"
    append algs "[be16 0x0805][be16 0x0501][be16 0x0806][be16 0x0601]"
    return [mkext 0x000d "[be16 [string length $algs]]$algs"]
}

# The published reference ClientHello: 1 GREASE + 15 ciphers, 16 extensions,
# ALPN h2, TLS 1.3 via supported_versions. Its JA3 and JA4 are published values,
# which is what makes test_parser_sanity a check of the spec.
proc corpus_reference {{legver 0x0303}} {
    set ciphers "[be16 0x0a0a][be16 0x1301][be16 0x1302][be16 0x1303]"
    append ciphers "[be16 0xc02b][be16 0xc02f][be16 0xc02c][be16 0xc030]"
    append ciphers "[be16 0xcca9][be16 0xcca8][be16 0xc013][be16 0xc014]"
    append ciphers "[be16 0x009c][be16 0x009d][be16 0x002f][be16 0x0035]"
    return [build_hello $ciphers [list \
        [ext_sni] [mkext 0x0017 ""] [mkext 0xff01 [be8 0]] [ext_curves] \
        [ext_pointfmt] [mkext 0x0023 ""] [ext_alpn] [mkext 0x0005 ""] \
        [ext_sigalgs_full] [mkext 0x0012 ""] [ext_keyshare] \
        [mkext 0x002d [binary format cc 1 1]] [ext_sv] \
        [mkext 0x001b [binary format ccc 2 0 2]] [mkext 0x4469 ""] \
        [ext_padding]] A "" $legver]
}
