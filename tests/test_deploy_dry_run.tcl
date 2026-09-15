# Run the template's implementation block, the tmsh-side Tcl a BIG-IP executes
# at deploy time, against stubbed tmsh commands. Nothing else runs it before a
# box does, and the 65535-character rule limit was found there, mid-deploy.
#
# What this pins: the deploy completes, every iRule is created, each body is
# under mcpd's limit after real substitution, no placeholder survives, and a
# substituted body still loads with the answers where the statics expect them,
# including answers that would end a double-quoted string.
source [file join [file dirname [info script]] assert.tcl]

set root [file join [file dirname [info script]] ..]
set fh [open [file join $root iApp MIDEYE_SHIELD.tmpl] r]
set tmpl [split [read $fh] "\n"]
close $fh

# --- the implementation block -------------------------------------------------
proc block_between {open close} {
    set start -1
    for { set i 0 } { $i < [llength $::tmpl] } { incr i } {
        set line [string trim [lindex $::tmpl $i]]
        if { $start < 0 && $line eq $open } { set start $i ; continue }
        if { $start >= 0 && $line eq $close } {
            # The line before "close" is the block's own closing brace.
            return [join [lrange $::tmpl [expr { $start + 1 }] [expr { $i - 2 }]] "\n"]
        }
    }
    error "no '$open' ... '$close' block in the template"
}
set implementation [block_between "implementation \{" "macro \{"]
assert {[string length $implementation] > 1000} "the implementation block was found"

# --- the form's default answers, from the presentation block ------------------
# Each "section x { string y ... default "v" }" becomes $::x__y, as the iApp
# framework does before running the implementation.
proc default_answers {} {
    set answers [list]
    set section ""
    foreach line $::tmpl {
        if { [regexp {^section (\w+) \{} $line -> s] } { set section $s ; continue }
        if { $section ne "" && [regexp {^\s*(?:string|choice) (\w+) .*default "([^"]*)"} $line -> field value] } {
            lappend answers "${section}__${field}" $value
        }
    }
    return $answers
}
set defaults [default_answers]
assert {[llength $defaults] >= 60} "the presentation block yields the form's defaults"

# --- a deploy ----------------------------------------------------------------
# Returns the created objects as a list of {kind name body} triples.
proc deploy {answers {existing_rule ""}} {
    set i [interp create]
    $i eval [list set ::EXISTING_RULE $existing_rule]
    $i eval {
        set ::CREATED [list]
        namespace eval ::tmsh {}
        proc ::tmsh::pwd {} { return "/Common/MIDEYE_SHIELD.app" }
        proc ::tmsh::log {msg} {}
        proc ::tmsh::get_name {obj} { return $obj }
        proc ::tmsh::get_field_value {obj field} { return "bigip-lab.example.com" }
        proc ::tmsh::get_config {args} {
            if { [string match "*ltm rule*" $args] } { return $::EXISTING_RULE }
            return [list "sys-global-settings"]
        }
        proc ::tmsh::create {args} {
            if { [llength $args] == 4 } {
                lappend ::CREATED [list [lrange $args 0 1] [lindex $args 2] [lindex $args 3]]
            } else {
                lappend ::CREATED [list [lrange [lindex $args 0] 0 1] [lindex [lindex $args 0] 2] ""]
            }
        }
        proc ::tmsh::modify {args} { lappend ::CREATED [list modify $args ""] }
        # "exec tmsh list ..." answers "" so the data groups read as missing and
        # are created; "exec tmsh -a create ltm data-group internal <path> ..."
        # is recorded like the rest.
        proc exec {args} {
            if { [lrange $args 0 1] eq "tmsh list" } { return "" }
            lappend ::CREATED [list [lrange $args 3 4] [lindex $args 6] ""]
            return ""
        }
        proc puts {args} {}
    }
    foreach {name value} $answers { $i eval [list set ::$name $value] }
    set failed [catch { $i eval $::implementation } err]
    set created [$i eval {set ::CREATED}]
    interp delete $i
    if { $failed } { error "deploy failed: $err" }
    return $created
}
proc created_body {created kind name} {
    foreach c $created {
        if { [lindex $c 0] eq $kind && [lindex $c 1] eq $name } { return [lindex $c 2] }
    }
    error "$kind $name was not created"
}
proc created_names {created} {
    set out [list]
    foreach c $created { lappend out "[lindex $c 0] [lindex $c 1]" }
    return [lsort $out]
}

# Load a substituted body the way the harnesses do, and return its statics.
proc statics_of {body} {
    set i [interp create]
    $i eval {
        rename dict ""
        namespace eval ::static {}
        proc when {event body} { if { $event eq "RULE_INIT" } { uplevel #0 $body } }
        proc call {target args} { return [uplevel 1 [linsert $args 0 [lindex [split $target ":"] end]]] }
    }
    $i eval $body
    set out [list]
    foreach v [lsort [$i eval {info vars ::static::*}]] { lappend out [namespace tail $v] [$i eval [list set $v]] }
    interp delete $i
    return $out
}

set RULES {MIDEYE_SHIELD_APM MIDEYE_SHIELD_COMMON MIDEYE_SHIELD_CONNECTION MIDEYE_SHIELD_TRAFFIC}

# --- defaults, existing HSSR ---------------------------------------------------
set threw [catch { set created [deploy $defaults] } err]
if { $threw } { puts "  $err" }
assert {$threw == 0} "the implementation completes with the form's defaults"

set names [created_names $created]
foreach r $RULES {
    assert {[lsearch -exact $names "ltm rule $r"] >= 0} "deploy creates $r"
}
assert {[lsearch -exact $names "ltm rule MIDEYE_SHIELD_HSSR"] < 0} "an existing HSSR is not reinstalled"
assert {[lsearch -exact $names "ltm data-group /Common/MIDEYE_SHIELD_WHITELIST"] >= 0} \
    "deploy creates the whitelist data group when it is missing"

foreach r $RULES {
    set body [created_body $created "ltm rule" $r]
    assert {[string length $body] <= 65535} \
        "$r is under tmsh's 65535-character limit after substitution ([string length $body])"
    assert {![regexp {__[a-z][a-z_]*__} $body]} "$r has no placeholder left after substitution"
}

set common [created_body $created "ltm rule" MIDEYE_SHIELD_COMMON]
array set st [statics_of $common]
assert {$st(MIDEYE_SHIELD_api_base_url) eq "https://shield.prod.mideye.com/api/v2"} \
    "a form answer reaches its static"
assert {$st(MIDEYE_SHIELD_traffic_device_hostname) eq "bigip-lab.example.com"} \
    "the device hostname resolved at deploy time reaches TRAFFIC's source id"
assert {[string length $st(MIDEYE_SHIELD_username_salt)] == 32} \
    "an empty salt answer is replaced by a generated 32-character salt"
assert {[string first "call /Common/HSSR::http_req" $common] >= 0} \
    "an existing HSSR answer becomes COMMON's call target"
array set tr [statics_of [created_body $created "ltm rule" MIDEYE_SHIELD_TRAFFIC]]
assert {[info exists tr(MIDEYE_SHIELD_traffic_max_record)]} "the substituted TRAFFIC body loads"

# --- install HSSR --------------------------------------------------------------
array set a $defaults
set a(hssr__mode) install
set created [deploy [array get a]]
set names [created_names $created]
assert {[lsearch -exact $names "ltm rule MIDEYE_SHIELD_HSSR"] >= 0}        "install mode creates the HSSR iRule"
assert {[lsearch -exact $names "ltm rule MIDEYE_SHIELD_HSSR_helper"] >= 0} "install mode creates the HSSR helper iRule"
assert {[lsearch -exact $names "ltm virtual MIDEYE_SHIELD_HSSR_helper_vs"] >= 0} "install mode creates the helper virtual server"
set common [created_body $created "ltm rule" MIDEYE_SHIELD_COMMON]
array set st [statics_of $common]
assert {[string first "call /Common/MIDEYE_SHIELD.app/MIDEYE_SHIELD_HSSR::http_req" $common] >= 0} \
    "install mode points COMMON at the HSSR it installed"
assert {$st(MIDEYE_SHIELD_hssr_helper_vs) eq "/Common/MIDEYE_SHIELD.app/MIDEYE_SHIELD_HSSR_helper_vs"} \
    "install mode points COMMON at the helper virtual server it created"

# --- an existing salt survives an upgrade ---------------------------------------
set rule "when RULE_INIT {\n    set static::MIDEYE_SHIELD_username_salt \"old-salt-with-\\\"quote\\\"\"\n}"
set created [deploy $defaults $rule]
array set st [statics_of [created_body $created "ltm rule" MIDEYE_SHIELD_COMMON]]
assert {$st(MIDEYE_SHIELD_username_salt) eq "old-salt-with-\"quote\""} \
    "the salt read back from a deployed rule round-trips through the escaper"

# --- answers that would end a double-quoted string --------------------------------
array set a $defaults
set a(api__base_url) {https://x/"quoted"\path$var[cmd]}
set a(traffic__sensor_id) {sensor "one"}
set threw [catch { set created [deploy [array get a]] } err]
if { $threw } { puts "  $err" }
assert {$threw == 0} "hostile answers do not break the deploy"
array set st [statics_of [created_body $created "ltm rule" MIDEYE_SHIELD_COMMON]]
assert {$st(MIDEYE_SHIELD_api_base_url) eq {https://x/"quoted"\path$var[cmd]}} \
    "a quote, backslash, dollar and brackets in an answer reach the static intact"
assert {$st(MIDEYE_SHIELD_traffic_sensor_id) eq {sensor "one"}} \
    "a quoted sensor id reaches TRAFFIC's static intact"

finish
