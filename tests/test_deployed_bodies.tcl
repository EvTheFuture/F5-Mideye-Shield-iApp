# The template embeds each iRule with its comments stripped, to stay under
# tmsh's 65535-character rule limit. What a BIG-IP runs is that copy, not the
# source, so it has to define the same procs, run the same RULE_INIT, and stay
# under the limit with room for substitution.
source [file join [file dirname [info script]] assert.tcl]

set root [file join [file dirname [info script]] ..]
set fh [open [file join $root iApp MIDEYE_SHIELD.tmpl] r]
set tmpl [split [read $fh] "\n"]
close $fh

# The generator emits "set _BODY_<name> {", the body, "}", a blank line and
# the next "# ----- " block marker.
proc body_of {name} {
    set start [lsearch -exact $::tmpl "set _BODY_$name \{"]
    if { $start < 0 } { error "no _BODY_$name block in the template" }
    for { set i [expr { $start + 1 }] } { $i < [llength $::tmpl] } { incr i } {
        if { [string match "# ----- *" [lindex $::tmpl $i]] } { break }
    }
    if { [lindex $::tmpl [expr { $i - 2 }]] ne "\}" } { error "_BODY_$name block does not end as expected" }
    return [join [lrange $::tmpl [expr { $start + 1 }] [expr { $i - 3 }]] "\n"]
}

# Load a body into a fresh interpreter with the iRule commands stubbed as the
# harnesses do, and report what it defined.
proc load {text} {
    set i [interp create]
    $i eval {
        rename dict ""
        namespace eval ::static {}
        proc when {event body} { if { $event eq "RULE_INIT" } { uplevel #0 $body } }
        proc call {target args} { return [uplevel 1 [linsert $args 0 [lindex [split $target ":"] end]]] }
    }
    $i eval $text
    set procs   [lsort [$i eval {info procs}]]
    set statics [lsort [$i eval {info vars ::static::*}]]
    interp delete $i
    return [list $procs $statics]
}

foreach name {MIDEYE_SHIELD_COMMON MIDEYE_SHIELD_TRAFFIC MIDEYE_SHIELD_CONNECTION MIDEYE_SHIELD_APM} {
    set fh [open [file join $root iRules $name.tcl] r]
    set src [read $fh]
    close $fh
    set deployed [body_of $name]

    assert {[string length $deployed] <= 65535 - 2048} \
        "$name deployed copy leaves room under tmsh's 65535-character limit"
    assert {[string first "Comments are stripped" $deployed] >= 0} \
        "$name deployed copy says its comments were stripped"

    set from_src [load $src]
    set from_tmpl [load $deployed]
    assert {[lindex $from_src 0] eq [lindex $from_tmpl 0]} \
        "$name deployed copy defines the same procs as the source"
    assert {[lindex $from_src 1] eq [lindex $from_tmpl 1]} \
        "$name deployed copy's RULE_INIT sets the same statics as the source"
}

# The license notice must survive stripping: the template is a redistribution.
assert {[string first "Copyright (c) 2024, FoxIO" [body_of MIDEYE_SHIELD_TRAFFIC]] >= 0} \
    "the BSD notice stays in the deployed MIDEYE_SHIELD_TRAFFIC"

finish
