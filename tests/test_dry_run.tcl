# COMMON documents dry run as "always returns 1 but logs what would have been
# denied". These tests pin that contract on every deny branch.
source [file join [file dirname [info script]] common_harness.tcl]

set ::LOGS      [list]
set ::BLACKLIST 0
set ::WHITELIST 0
set ::SCORE     0

proc LOG_WARNING {args} { lappend ::LOGS "WARNING [join $args]" }
proc LOG_INFO    {args} { lappend ::LOGS "INFO [join $args]" }
proc LOG_DEBUG   {args} {}
proc class {op value cmp dg} {
    if { [string match "*BLACKLIST" $dg] } { return $::BLACKLIST }
    if { [string match "*WHITELIST" $dg] } { return $::WHITELIST }
    return 0
}
proc _FETCH_IP_SCORE {client_ip cache_time} { return $::SCORE }

set static::MIDEYE_SHIELD_disabled         0
set static::MIDEYE_SHIELD_score_hard_deny  80
set static::MIDEYE_SHIELD_score_warn       50

proc reset {dry} {
    array unset ::TBL
    array unset ::TBL_EXP
    set ::LOGS      [list]
    set ::BLACKLIST 0
    set ::WHITELIST 0
    set ::SCORE     0
    set static::MIDEYE_SHIELD_dry_run $dry
}
proc logged {pattern} {
    foreach l $::LOGS { if { [string match $pattern $l] } { return 1 } }
    return 0
}

# --- dry run denies nothing -------------------------------------------------
reset 1
set ::BLACKLIST 1
assert {[_VALIDATE 1.2.3.4 300] == 1} "dry run allows a blacklisted IP"
assert {[logged "*DRY RUN*"] == 1} "dry run says what it would have denied (blacklist)"
assert {[table lookup -subtable "MIDEYE_SHIELD" "stat_blacklisted"] == 1} \
    "dry run still counts the blacklist hit"

reset 1
set ::SCORE 90
assert {[_VALIDATE 1.2.3.4 300] == 1} "dry run allows a high-score IP"
assert {[logged "*DRY RUN*"] == 1} "dry run says what it would have denied (score)"

# --- enforcement still denies -----------------------------------------------
reset 0
set ::BLACKLIST 1
assert {[_VALIDATE 1.2.3.4 300] == 0} "enforcing denies a blacklisted IP"

reset 0
set ::SCORE 90
assert {[_VALIDATE 1.2.3.4 300] == 0} "enforcing denies a high-score IP"

reset 0
set ::SCORE 10
assert {[_VALIDATE 1.2.3.4 300] == 1} "a low score is allowed"

# The score would deny on its own, so this fails if the whitelist stops
# taking precedence.
reset 0
set ::WHITELIST 1
set ::SCORE 90
assert {[_VALIDATE 1.2.3.4 300] == 1} "a whitelisted IP is allowed"

finish
