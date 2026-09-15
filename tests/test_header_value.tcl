# Which header values may leave the device, and how much of each. The caller
# only reads a value when this returns a cap, so "" means the value is never
# fetched from the request at all.
source [file join [file dirname [info script]] fp_harness.tcl]

assert {[_HEADER_VALUE_CAP "Host"] == 255}            "host value ships"
assert {[_HEADER_VALUE_CAP "HOST"] == 255}            "the name match is case-insensitive"
assert {[_HEADER_VALUE_CAP "Accept-Language"] == 255} "accept-language value ships"
assert {[_HEADER_VALUE_CAP "Cookie"] eq ""}           "cookie value is never read"
assert {[_HEADER_VALUE_CAP "Authorization"] eq ""}    "authorization value is never read"
assert {[_HEADER_VALUE_CAP "User-Agent"] eq ""} \
    "user-agent ships from its own field, never through the header loop"

# Host is capped to the same length as destination.application.id, so a long
# Host cannot inflate an event beyond what that field already costs.
assert {[_HEADER_VALUE_CAP "Host"] == [_HEADER_VALUE_CAP "Accept-Language"]} \
    "no shipped header value is allowed to be larger than another"

finish
