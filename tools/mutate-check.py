#!/usr/bin/env python3
"""Break one behaviour at a time and require the test suite to notice.

A passing test may assert something the code cannot violate. Each mutation
below flips one real behaviour, and at least one test must then fail.

  NOT CAUGHT  the tests have a hole - the mutated behaviour is unasserted.
  NO MATCH    the anchor text is gone, so this check has been testing nothing.
              A refactor moved the code; re-point the anchor.

Usage: tools/mutate-check.py
"""

import glob
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRAFFIC = "iRules/MIDEYE_SHIELD_TRAFFIC.tcl"
COMMON = "iRules/MIDEYE_SHIELD_COMMON.tcl"
# Generated, and mutated here anyway: it carries the tmsh-side procs, and it is
# the copy a BIG-IP runs. Restored like any other file.
TMPL = "iApp/MIDEYE_SHIELD.tmpl"

# (file, exact text to replace, replacement, behaviour being broken)
MUTATIONS = [
    # --- buffering and flushing (the shared event buffer in COMMON) ---
    # The saving is only safe while both paths agree.
    (COMMON,
     "if { ![regexp {[^ -~]} $value] } {",
     "if { 1 } {",
     "a value with a byte outside printable ASCII takes the full escape map"),
    # Loss that nothing counts reads as no loss at all.
    (COMMON,
     "            incr EMPTY",
     "            set EMPTY $EMPTY",
     "an empty slot at flush time is counted and reported"),
    # Scale is not an exception to rejecting a partial parse.
    (TRAFFIC,
     "        if { [incr cs_iter] > $static::MIDEYE_SHIELD_traffic_max_iter } { return \"\" }",
     "        if { [incr cs_iter] > $static::MIDEYE_SHIELD_traffic_max_iter } { break }",
     "more ciphers than the iteration bound rejects the hello"),
    (TRAFFIC,
     'if { [incr iter] > $static::MIDEYE_SHIELD_traffic_max_iter } { return "REJECT" }',
     'if { [incr iter] > $static::MIDEYE_SHIELD_traffic_max_iter } { break }',
     "an over-long u16 vector rejects the hello"),
    (COMMON,
     "set TTL [expr { $T * 2 + 360 }]",
     "set TTL 120",
     "the event TTL follows the flush interval"),
    (COMMON,
     "set TTL [expr { $T * 2 + 360 }]",
     "set TTL [expr { $T * 2 + 60 }]",
     "an event outlives a keep-alive connection's idle timeout"),
    (COMMON,
     "if { $N > $MAXBUF } { set N $MAXBUF }",
     "if { 0 } { set N $MAXBUF }",
     "the batch size is clamped to the buffer cap"),
    (COMMON,
     "if { $BUFFERED > $MAXBUF } {",
     "if { 0 } {",
     "events past the cap are dropped"),
    (COMMON,
     "if { [llength $EVENTS] > 0 && [expr { $BYTES + $SIZE }] > $MAXBYTES } { break }",
     "if { 0 } { break }",
     "a batch stops before the body outgrows the byte cap"),
    (COMMON,
     'table set -subtable $sub "cursor" $TAKEN indefinite indefinite',
     'table set -subtable $sub "cursor" $END indefinite indefinite',
     "a capped flush leaves the remainder for the next one"),
    (COMMON,
     "if { [llength $EVENTS] > 0 && [expr { $BYTES + $SIZE }] > $MAXBYTES } { break }",
     "if { [expr { $BYTES + $SIZE }] > $MAXBYTES } { break }",
     "an event bigger than the cap goes rather than blocking the cursor"),
    (COMMON,
     "set END [expr { $CURSOR + 1000 }]",
     "set END [expr { $CURSOR + 5000 }]",
     "a POST carries at most 1000 events"),

    # --- deferring the POST off the request path ---
    (COMMON,
     "if { $FIRST eq \"\" || ([clock seconds] - $FIRST) >= $T * 2 } { set DUE 1 }",
     "if { 1 } { set DUE 1 }",
     "a deferring caller does not POST from the request path"),
    (COMMON,
     "if { $FIRST eq \"\" || ([clock seconds] - $FIRST) >= $T * 2 } { set DUE 1 }",
     "if { 0 } { set DUE 1 }",
     "a caller whose connections never close still flushes"),
    (COMMON,
     "if { $FIRST eq \"\" || ([clock seconds] - $FIRST) >= $T * 2 } { set DUE 1 }",
     "if { $FIRST eq \"\" || ([clock seconds] - $FIRST) >= $T } { set DUE 1 }",
     "the request path leaves the first interval to the close path"),

    # --- the buffer's clock is its oldest event ---
    (COMMON,
     "if { $BUFFERED >= $N || $FIRST eq \"\" || ([clock seconds] - $FIRST) >= $T } {",
     "if { $BUFFERED >= $N } {",
     "a close drains a partial batch once its oldest event has waited the interval"),
    (COMMON,
     "if { $BUFFERED >= $N || $FIRST eq \"\" || ([clock seconds] - $FIRST) >= $T } {",
     "if { $BUFFERED >= $N || ($FIRST ne \"\" && ([clock seconds] - $FIRST) >= $T) } {",
     "what a capped flush leaves behind is taken by the next close"),
    (COMMON,
     '    table delete -subtable $sub "first_buffered"',
     '    # table delete -subtable $sub "first_buffered"',
     "a flush resets the clock"),
    (COMMON,
     'table add -subtable $sub "first_buffered" [clock seconds] indefinite indefinite',
     'table set -subtable $sub "first_buffered" [clock seconds] indefinite indefinite',
     "the clock is the oldest event's, not the newest's"),
    (COMMON,
     "    if { $BUFFERED >= $BACKSTOP } { set DUE 1 } else {",
     "    if { 0 } { set DUE 1 } else {",
     "the backstop flushes inline before the buffer can drop events"),
    (COMMON,
     'if { [table lookup -subtable $sub "backoff"] ne "" } { return 0 }',
     "if { 0 } { return 0 }",
     "a backed-off buffer is not due from the request path"),
    (COMMON,
     "set PAUSE [call /__partition__/MIDEYE_SHIELD_COMMON::_BACK_OFF $sub]",
     "set PAUSE 0",
     "a failed POST backs off before the next attempt"),
    (COMMON,
     "    set BACKSTOP [expr { $N * 2 }]",
     "    set BACKSTOP $N",
     "the backstop leaves a deferring caller room past the batch size"),
    (COMMON,
     "    if { $BACKSTOP > $HALF } { set BACKSTOP $HALF }",
     "    if { 0 } { set BACKSTOP $HALF }",
     "a raised buffer cap does not push the backstop out of reach"),
    (COMMON,
     "    if { $BUFFERED < 1 } { return }",
     "    if { 0 } { return }",
     "a close with nothing buffered does no work"),
    (COMMON,
     'call /__partition__/MIDEYE_SHIELD_COMMON::_ENQUEUE_EVENT "MIDEYE_SHIELD_BLOCKS"',
     'call /__partition__/MIDEYE_SHIELD_COMMON::_ENQUEUE_EVENT_DEFERRED "MIDEYE_SHIELD_BLOCKS"',
     "block reporting flushes inline rather than deferring"),
    (TRAFFIC,
     'call /__partition__/MIDEYE_SHIELD_COMMON::_ENQUEUE_EVENT_DEFERRED "MIDEYE_SHIELD_TRAFFIC"',
     'call /__partition__/MIDEYE_SHIELD_COMMON::_ENQUEUE_EVENT "MIDEYE_SHIELD_TRAFFIC"',
     "traffic reporting defers its flush"),
    (TRAFFIC,
     'call /__partition__/MIDEYE_SHIELD_COMMON::_FLUSH_IF_DUE "MIDEYE_SHIELD_TRAFFIC"',
     'call /__partition__/MIDEYE_SHIELD_COMMON::_FLUSH_IF_DUE "MIDEYE_SHIELD_BLOCKS"',
     "the close event flushes the buffer the request path wrote to"),

    # --- the connection's events ---
    (TRAFFIC,
     "    if { $static::MIDEYE_SHIELD_traffic_enabled == 1 } {",
     "    if { 1 } {",
     "CLIENT_ACCEPTED collects only when reporting is enabled"),
    (TRAFFIC,
     "            set ms_traffic_ch_pending 0",
     "            # set ms_traffic_ch_pending 0",
     "the ordering warning is said once per connection"),
    (TRAFFIC,
     "            catch { set sid [info hostname] }",
     "            catch { set sid \"\" }",
     "an empty baked hostname falls back to the runtime hostname"),

    # --- the deploy itself (test_deploy_dry_run.tcl runs the implementation) ---
    (TMPL,
     "tmsh::create ltm rule MIDEYE_SHIELD_TRAFFIC $_BODY_MIDEYE_SHIELD_TRAFFIC",
     "# tmsh::create ltm rule MIDEYE_SHIELD_TRAFFIC $_BODY_MIDEYE_SHIELD_TRAFFIC",
     "the deploy creates every iRule"),
    (TMPL,
     '"__api__base_url__" "[_escape_answer $::api__base_url]"',
     '"__api__base_url__" "$::api__base_url"',
     "an answer is escaped on its way into a rule body"),

    # --- the flush lock ---
    (COMMON,
     'set TICKET [table incr -subtable $sub "ticket"]',
     "set TICKET 1",
     "each flusher holds a ticket no other flusher can hold"),
    (COMMON,
     'if { [table lookup -subtable $sub "flush_lock"] eq $ticket } {',
     "if { 1 } {",
     "a lapsed flusher does not free its successor's lock"),

    # --- failures are visible ---
    (COMMON,
     'if { $FAILURE ne "" } {',
     "if { 0 } {",
     "a failed flush is logged"),
    (COMMON,
     'if { $DROPPED ne "" && $DROPPED > 0 } {',
     "if { 0 } {",
     "buffer overflow is reported"),

    # --- event shape and privacy ---
    (TRAFFIC,
     '"host"            { return 255 }',
     '"host"            { return 8191 }',
     "Host ships no more than destination.application.id does"),
    # The release belongs to the connection; a throw must not take it too.
    (TRAFFIC,
     "\"traffic-intel: ClientHello capture failed -> '$err'\"",
     '\"x\"; return',
     "a throw while fingerprinting still reaches TCP::release"),
    (TRAFFIC,
     "set ms_traffic_reported 1",
     "set ms_traffic_reported_unused 1",
     "the full fingerprint is sent once per connection, not every request"),
    (TRAFFIC,
     "catch { set sid [info hostname] }",
     "catch { set sid $sid }",
     "an empty baked hostname falls back to the runtime hostname"),
    (TRAFFIC,
     ',\\"type\\":\\"enforcement_point\\"',
     ',\\"type\\":\\"lab\\"',
     "the source type never claims a raw-capture-enabling sensor type"),

    # --- form answers on their way into an iRule body ---
    (TMPL,
     "        lappend map [format %c $code] $bs[format %c $code]",
     "        lappend map [format %c $code] [format %c $code]",
     "an answer's TCL metacharacters are escaped, not passed through"),
    (TMPL,
     "        lappend map $bs[format %c $code] [format %c $code]",
     "        lappend map [format %c $code] [format %c $code]",
     "an answer read back out of a deployed iRule is unescaped"),

    # --- event size bounds ---
    (TRAFFIC,
     "if { $hcount >= 100 || $hbytes >= $static::MIDEYE_SHIELD_traffic_max_headers } { break }",
     "if { $hcount >= 100 } { break }",
     "the header block is bounded in bytes, not only in count"),
    (TRAFFIC,
     "if { [string length $event] <= $static::MIDEYE_SHIELD_traffic_max_event } {",
     "if { 1 } {",
     "an oversized event never reaches the buffer"),

    # --- ClientHello parsing ---
    (TRAFFIC,
     "if { [info exists ext_seen($et_hex)] } { return \"\" }",
     'if { 0 } { return "" }',
     "a repeated extension type rejects the hello"),
    (TRAFFIC,
     "if { [scan $hs_len_hex %x] != ($total_needed - 9) } {",
     "if { 0 } {",
     "a handshake split across records is rejected"),
    (TRAFFIC,
     "set ver    [scan $hello(ver_hex) %x]",
     "set ver    771",
     "JA3 keys on the legacy client_version"),
    (TRAFFIC,
     'if { $data_start + $et_len > $ext_end } { return "" }',
     'if { 0 } { return "" }',
     "an extension running past the block is rejected before its vector is read"),
    (TRAFFIC,
     "if { $off + $len_bytes > $limit } { return \"REJECT\" }",
     'if { 0 } { return "" }',
     "a length prefix running past the record is rejected"),
    (TRAFFIC,
     'if { ($vec_len % 2) != 0 || $end > $limit } { return "REJECT" }',
     'if { ($vec_len % 2) != 0 || $end > $limit } { return "" }',
     "a vector running past its extension rejects the hello"),
    (TRAFFIC,
     '    if { $end > $limit } { return "REJECT" }',
     '    if { $end > $limit } { return "" }',
     "a point-formats vector running past its extension rejects the hello"),
    (TRAFFIC,
     '            if { $off != $ext_end } { return "" }',
     '            if { 0 } { return "" }',
     "trailing bytes inside the extension block reject the hello"),
    (TRAFFIC,
     "if { $off + $ext_total_len == $total_needed } {",
     "if { $off + $ext_total_len <= $total_needed } {",
     "bytes after the extension block reject the hello"),
    (TRAFFIC,
     "($entry & 0x0f0f) == 0x0a0a",
     "($entry & 0x0f0f) == 0xffff",
     "GREASE inside a vector is stripped"),
    (TRAFFIC,
     "($cs_int & 0x0f0f) == 0x0a0a",
     "($cs_int & 0x0f0f) == 0xffff",
     "GREASE cipher suites are stripped"),
    (TRAFFIC,
     "($et_int & 0x0f0f) == 0x0a0a",
     "($et_int & 0x0f0f) == 0xffff",
     "GREASE extensions are stripped"),
]


def suite_fails():
    """True when at least one test file fails or errors."""
    for test in sorted(glob.glob(str(ROOT / "tests" / "test_*.tcl"))):
        result = subprocess.run(
            ["tclsh", test], cwd=ROOT, capture_output=True, text=True
        )
        if result.returncode != 0:
            return True
    return False


def main():
    if suite_fails():
        sys.stderr.write(
            "The suite already fails before any mutation. Fix that first -\n"
            "this check can only tell you something when the baseline is green.\n"
        )
        return 1

    problems = 0
    for rel_path, old, new, description in MUTATIONS:
        path = ROOT / rel_path
        # open() rather than read_text(newline=...), which needs Python 3.13;
        # CI runs 3.12. newline="" keeps CRLF/LF intact for exact write-back.
        with path.open(encoding="utf-8", newline="") as f:
            original = f.read()

        occurrences = original.count(old)
        if occurrences != 1:
            print(f"NO MATCH    {description}")
            print(f"            {occurrences} occurrences of: {old}")
            problems += 1
            continue

        try:
            path.write_text(
                original.replace(old, new), encoding="utf-8", newline=""
            )
            caught = suite_fails()
        finally:
            path.write_text(original, encoding="utf-8", newline="")

        if caught:
            print(f"caught      {description}")
        else:
            print(f"NOT CAUGHT  {description}")
            problems += 1

    print("----")
    if problems:
        print(f"{len(MUTATIONS)} mutations, {problems} unaccounted for")
        return 1
    print(f"{len(MUTATIONS)} mutations, all caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
