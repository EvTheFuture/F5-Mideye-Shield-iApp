# =============================================================================
# common_harness.tcl - load MIDEYE_SHIELD_COMMON.tcl procs into plain tclsh.
#
# TMM runs a Tcl 8.4 interpreter with no `dict`; kill it here so any accidental
# use in the sourced procs fails loudly rather than passing on a desktop 8.6.
# =============================================================================
rename dict ""

# Run the iRule's own RULE_INIT so constants under test come from the source of
# truth rather than a copy here that drifts. Other event bodies are kept so a
# test can drive them against stubbed iRule commands.
array set ::EVENT_BODY {}
proc when {event body} {
    if { $event eq "RULE_INIT" } { uplevel #0 $body }
    set ::EVENT_BODY($event) $body
}

namespace eval ::static {}

# In TMM a proc is reached as `call /__partition__/RULE::PROC`; here they are
# plain procs, so dispatch on the name after the last colon.
proc call {target args} {
    return [uplevel 1 [linsert $args 0 [lindex [split $target ":"] end]]]
}

# --- clock ------------------------------------------------------------------
# Fixed and advanced by hand, so the time-based flush trigger and the per-event
# TTL are tested rather than waited for.
set ::NOW 1786000000
proc clock {sub args} {
    switch -- $sub {
        seconds { return $::NOW }
        format  { return "2026-08-14T09:00:00+0200" }
    }
}
proc advance {secs} { incr ::NOW $secs }

# --- session table ----------------------------------------------------------
# `table incr` and `table add` are atomic on a real BIG-IP; here they are simply
# indivisible, which is the property the buffer relies on.
array set ::TBL     {}
array set ::TBL_EXP {}

# F5 documents that `table add` does not overwrite an existing entry, but not
# what it hands back when it declines. The flush lock must not depend on the
# answer, so lock tests run under both readings.
set ::TABLE_ADD_RETURNS_EXISTING 1

proc _tbl_expire {} {
    foreach k [array names ::TBL_EXP] {
        if { $::TBL_EXP($k) <= $::NOW } { unset -nocomplain ::TBL($k) ::TBL_EXP($k) }
    }
}
proc _tbl_ttl {k timeout} {
    unset -nocomplain ::TBL_EXP($k)
    if { $timeout eq "" || $timeout eq "indefinite" } { return }
    set ::TBL_EXP($k) [expr { $::NOW + $timeout }]
}
proc table {op args} {
    set sub ""
    if { [lindex $args 0] eq "-subtable" } {
        set sub  [lindex $args 1]
        set args [lrange $args 2 end]
    }
    _tbl_expire
    set k   "$sub/[lindex $args 0]"
    set val [lindex $args 1]
    switch -- $op {
        set {
            set ::TBL($k) $val
            _tbl_ttl $k [lindex $args 2]
            return $val
        }
        add {
            if { [info exists ::TBL($k)] } {
                if { $::TABLE_ADD_RETURNS_EXISTING } { return $::TBL($k) }
                return ""
            }
            set ::TBL($k) $val
            _tbl_ttl $k [lindex $args 2]
            return $val
        }
        incr {
            if { $val eq "" } { set val 1 }
            if { ![info exists ::TBL($k)] } { set ::TBL($k) 0 }
            incr ::TBL($k) $val
            return $::TBL($k)
        }
        lookup { if { [info exists ::TBL($k)] } { return $::TBL($k) } ; return "" }
        delete { unset -nocomplain ::TBL($k) ::TBL_EXP($k) ; return "" }
    }
}

# --- iRule commands ---------------------------------------------------------
set ::VIRTUAL_NAME "/Common/vs_test"
proc virtual {args} { return $::VIRTUAL_NAME }

source [file join [file dirname [info script]] .. iRules MIDEYE_SHIELD_COMMON.tcl]

# --- tiny assertion kit -----------------------------------------------------
set ::pass 0
set ::fail 0
proc assert {cond label} {
    if { [uplevel 1 [list expr $cond]] } {
        incr ::pass
        puts "PASS  $label"
    } else {
        incr ::fail
        puts "FAIL  $label"
    }
}
proc finish {} {
    puts "----"
    puts "$::pass passed, $::fail failed"
    exit [expr { $::fail > 0 ? 1 : 0 }]
}
