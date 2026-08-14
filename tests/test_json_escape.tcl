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

finish
