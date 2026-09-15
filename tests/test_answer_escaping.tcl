# Form answers on their way into a double-quoted TCL string in an iRule body.
#
# These procs run under tmsh, not TMM, so no other test here reaches them and
# the generator only ever writes them out - a proc body is not parsed until it
# is called, so one that cannot parse gets discovered on a customer's box
# mid-deployment. This test takes them out of the generated template, which is
# the artifact a BIG-IP actually executes, and calls them.
source [file join [file dirname [info script]] assert.tcl]

set fh [open [file join [file dirname [info script]] .. iApp MIDEYE_SHIELD.tmpl]]
set tmpl [read $fh]
close $fh

# Lift one proc out of the template: its header line through the closing brace
# in column 0. Inner blocks close indented, so only the proc's own brace ends
# the scan.
proc proc_body {text name} {
    set out [list]
    set inside 0
    foreach line [split $text "\n"] {
        if { !$inside && [string match "proc $name *" $line] } { set inside 1 }
        if { $inside } {
            lappend out $line
            if { $line eq "\}" } { return [join $out "\n"] }
        }
    }
    return ""
}

foreach name {_escape_answer _unescape_answer} {
    set body [proc_body $tmpl $name]
    assert {$body ne ""} "$name is in the generated template"
    eval $body
}

# Every answer is free text from the iApp form, so these are the shapes an
# administrator can put in one - by accident or on purpose.
set cases [list \
    {plainSalt123} \
    {a$b} \
    {a[b]c} \
    {a\b} \
    {a"b} \
    {m\$x"y[z]} \
    {$[\]"} \
    {[clock seconds]} \
    {"; log local0. injected; set x "} \
]

foreach s $cases {
    set esc [_escape_answer $s]

    # The contract: substituted into a double-quoted string in an iRule body,
    # it must parse and come back as exactly what was typed. Anything else is
    # either a failed iRule load or an injection.
    set reloaded "<threw>"
    catch { eval "set reloaded \"$esc\"" }
    assert {$reloaded eq $s} "escaped answer reloads unchanged: $s"

    assert {[_unescape_answer $esc] eq $s} "escaping round-trips: $s"
}

# The salt is the one answer read back out of a deployed iRule, when the
# administrator clears the field and expects the old value to survive. Without
# the unescape it is escaped twice and silently changes, which invalidates
# every username hashed under it.
set salt {p@ss$w[o]rd\"}
set rule "when RULE_INIT \{\n    set static::MIDEYE_SHIELD_username_salt \"[_escape_answer $salt]\"\n    set static::MIDEYE_SHIELD_dns \"\"\n\}"
set recovered ""
regexp -line {^\s*set static::MIDEYE_SHIELD_username_salt\s+"(.*)"\s*$} $rule -> recovered
assert {[_unescape_answer $recovered] eq $salt} "a deployed salt reads back as itself"

finish
