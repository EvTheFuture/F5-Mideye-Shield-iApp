# Print a hex ClientHello of a given shape, for replaying against a lab BIG-IP.
# Not a test - `make test` only runs test_*.tcl.
#
# Usage: tclsh emit_blob.tcl small|large
source [file join [file dirname [info script]] fp_harness.tcl]

proc many_ciphers {n} {
    # n real ciphers from a fixed pool (values only need to look plausible)
    set pool {0x1301 0x1302 0x1303 0xc02b 0xc02f 0xc02c 0xc030 0xcca9 0xcca8 0xc013 0xc014 0x009c 0x009d 0x002f 0x0035 0x000a}
    set out ""
    for {set i 0} {$i < $n} {incr i} { append out [be16 [lindex $pool [expr {$i % [llength $pool]}]]] }
    return $out
}

set shape [lindex $argv 0]
switch -- $shape {
    small {
        # OpenSSL/curl-grade: ~30 ciphers, 9 extensions, no GREASE
        set hello [build_hello [many_ciphers 30] [list [ext_sni] [ext_curves] [ext_pointfmt] \
            [ext_sigalgs] [ext_alpn] [ext_sv] [ext_keyshare] \
            [mkext 0x0017 ""] [mkext 0x0023 ""]]]
    }
    large {
        # Chrome-grade: GREASE cipher + 15 real, 17 extensions incl GREASE + big padding
        set ciphers "[be16 0x0a0a][many_ciphers 15]"
        set exts [list [mkext 0x2a2a ""] [ext_sni] [mkext 0x0017 ""] [mkext 0xff01 [be8 0]] \
            [ext_curves] [ext_pointfmt] [mkext 0x0023 ""] [ext_alpn] [mkext 0x0005 ""] \
            [ext_sigalgs] [mkext 0x0012 ""] [ext_keyshare] [mkext 0x002d [binary format cc 1 1]] \
            [ext_sv] [mkext 0x001b [binary format ccc 2 0 2]] [mkext 0x4469 ""] [ext_padding 180]]
        set hello [build_hello $ciphers $exts]
    }
    default { puts stderr "usage: tclsh emit_blob.tcl small|large"; exit 2 }
}
binary scan $hello H* hex
puts $hex
