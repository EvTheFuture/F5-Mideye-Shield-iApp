# A single byte of invalid UTF-8 makes the whole batch POST unparseable,
# dropping up to 1000 buffered events from other clients.
source [file join [file dirname [info script]] common_harness.tcl]

assert {[_JSON_ESCAPE {plain}] eq {plain}} "plain string is unchanged"
assert {[_JSON_ESCAPE "a\"b"] eq {a\"b}} "double quote is escaped"
assert {[_JSON_ESCAPE "a\\b"] eq {a\\b}} "backslash is escaped"
assert {[_JSON_ESCAPE "a\nb"] eq {a\nb}} "newline becomes \\n"
assert {[_JSON_ESCAPE "a\tb"] eq {a\tb}} "tab becomes \\t"
assert {[_JSON_ESCAPE [format %c 1]] eq {\u0001}} "C0 control becomes \\u00xx"
assert {[_JSON_ESCAPE [format %c 255]] eq {\u00ff}} "non-ASCII byte becomes \\u00xx"
assert {[_JSON_ESCAPE {/Common/vs_test}] eq {/Common/vs_test}} "virtual server path is unchanged"

# The fast path is only safe while it and the full map agree exactly, so pin
# that over every byte value rather than trusting the reasoning.
proc _JSON_ESCAPE_FULL { value } {
    return [string map $static::MIDEYE_SHIELD_json_map $value]
}
set mismatched [list]
for { set c 0 } { $c < 256 } { incr c } {
    set s "x[format %c $c]y"
    if { [_JSON_ESCAPE $s] ne [_JSON_ESCAPE_FULL $s] } { lappend mismatched $c }
}
assert {[llength $mismatched] == 0} "fast path agrees with the full map on every byte value"

# A value that is printable ASCII apart from one byte must still take the full
# map, or that byte would leave unescaped.
assert {[_JSON_ESCAPE "ok[format %c 200]ok"] eq {ok\u00c8ok}} "one high byte in an ASCII value still escapes"
assert {[_JSON_ESCAPE "a b\"c\\d~"] eq {a b\"c\\d~}} "the fast path still escapes quote and backslash"

finish
