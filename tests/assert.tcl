# Tiny assertion kit, shared by every test and harness here.
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
