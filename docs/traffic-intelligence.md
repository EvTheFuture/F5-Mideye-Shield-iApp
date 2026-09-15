# Traffic intelligence

`MIDEYE_SHIELD_TRAFFIC` reports TLS and HTTP client fingerprints for every
connection that reaches a Virtual Server it is applied to, not only for
authentication attempts. Reporting is **on by default**.

Deploying the iApp creates the iRule but does not attach it to anything.
Applying it to a Virtual Server is what starts reporting, and it is the only
step — there is no second switch to find.

This document covers what the feature sends and why it is built the way it is.
The iRule itself is `iRules/MIDEYE_SHIELD_TRAFFIC.tcl`.

## Before you apply it

**The client must speak first.** `CLIENT_ACCEPTED` calls `TCP::collect` to
capture the handshake, and per F5's documentation *"Ordinarily, TCP::collect
causes the server-side connection to be delayed until the requested data is
received."* On a protocol where the **server** greets first — SSH, SMTP, FTP,
MySQL — the client sends nothing, so `CLIENT_DATA` never fires, `TCP::release`
is never reached, the serverside is never established, and the connection hangs
until the TCP profile's idle timeout. Every connection, for as long as the iRule
is attached.

That makes this iRule safe on TLS and HTTP Virtual Servers, and **unsafe on a
general-purpose TCP Virtual Server** carrying mixed protocols — a firewall-facing
one especially. Fingerprint on the Virtual Servers whose traffic you actually
want fingerprinted rather than attaching it broadly.

`MIDEYE_SHIELD_CONNECTION` does not have this constraint. It collects only when
a connection is waiting on another connection's in-flight score lookup, and
releases within `api_timeout` either way.

Order matters when it shares a Virtual Server with `MIDEYE_SHIELD_CONNECTION`.
List `MIDEYE_SHIELD_TRAFFIC` after it, so the enforcement decision completes
first. Reporting must never delay a block.

The wrong way round, `MIDEYE_SHIELD_CONNECTION` releases the handshake before
this iRule can read it: events still arrive, with no TLS fingerprint on any of
them. That logs `no ClientHello captured` once per connection rather than
failing silently.

## Turning it off

Set *Report client fingerprints for all traffic* to **No** in the iApp. The
iRule stays loaded and goes inert: `CLIENT_ACCEPTED` stops collecting the
handshake and `HTTP_REQUEST` returns immediately, so nothing is parsed,
buffered or sent. Removing the iRule from the Virtual Server has the same
effect.

## What is reported

The TLS handshake happens once per connection, so the fingerprint and the
client's header ordering cannot change between requests on that connection.
They are reported on the first request only. Every later request reports what
can differ — the method and the destination — plus the JA4, which is what ties
those requests back to the client that made them when several clients share an
address.

| | First request | Later requests |
|---|---|---|
| `ipAddress`, `observedAt` | ✓ | ✓ |
| `tlsContext.ja4` | ✓ | ✓ |
| `tlsContext.ja3`, `.version`, `.alpn`, `.cipherSuite` | ✓ | |
| `httpContext.method` | ✓ | ✓ |
| `httpContext.userAgent`, `.headers`, `.httpVersion` | ✓ | |
| `destination.application` (host), `.resource` (path) | ✓ | ✓ |
| `source` (sensor identity) | ✓ | ✓ |

A slim event is under a third the size of a full one, which is what makes
reporting on all traffic affordable.

### Privacy

Everything that leaves the device, exhaustively:

- **Header names**, in the order the client sent them, up to the first 100 and
  to a byte budget (see [Size](#size)). The order is the fingerprint; the
  Shield API stores a hash of it. `Cookie` is included by name because its
  presence is a fingerprint ingredient — its value is never read.
- **Three header values**, each capped at 256 characters (User-Agent at 4096):
  - `User-Agent` — the client identity the feature exists to record.
  - `Host` — the same string already leaves as `destination.application.id`.
  - `Accept-Language` — names languages, not a person.
- **The request method**, and **the path without its query string**, capped at
  1024 characters.
- **This device's hostname**, as the sensor id, unless the iApp sets one.

Every byte outside printable ASCII leaves as `\u00xx`, one escape per byte, so
a UTF-8 value arrives as its Latin-1 reading. That is deterministic and the
receiver can undo it; it is not readable as text until it does.

Dropping the query string keeps out the secrets applications put there by
convention, but the path itself is reported in full. An application that puts a
secret in a path segment — a password-reset link, a signed download URL —
reports that secret. Check your own URL shapes before applying the iRule to a
Virtual Server that serves them.

JA3 and JA4 are one-way hashes. The headers listed in
`traffic_forbidden_headers` — `Authorization`, `Set-Cookie`, `X-Api-Key`,
`X-Auth-Token`, `Proxy-Authorization`, `X-Csrf-Token`, `X-Xsrf-Token` — are not
reported at all, not even by name.

The header loop tests each name against `_HEADER_VALUE_CAP` **before** fetching
anything, so a `Cookie` value never enters Tcl in the first place. `Host` is
capped to the same length as `destination.application.id` so it cannot be used
to inflate an event beyond what that field already costs.

### Sensor identity

Every event carries a `source` block naming the observer:

```
id    the iApp's sensor id, or the hostname resolved at deploy time,
      or the runtime hostname
type  always "enforcement_point"
```

Each unit of an HA pair resolves its own hostname, which is the intent: the
sensor is the box that saw the request, not the cluster. The deploy-time lookup
is guarded — an optional telemetry label must never fail a deployment — so it
can come up empty, and the runtime hostname is the last fallback. Without it a
default deployment would ship every event unattributed.

The type is fixed rather than configurable. Only the honeypot and lab sensor
types opt traffic into Shield-side raw request capture, and a BIG-IP is
neither; hard-coding the type keeps customer traffic out of raw capture by
construction rather than by a dropdown nobody changed.

## What it cannot tell you

Three limits worth knowing before you read the data:

- **An HTTP profile is required.** Events are built in `HTTP_REQUEST`, so a TLS
  Virtual Server without an HTTP profile collects and parses the handshake and
  then reports nothing at all — silently, for as long as it is attached.
- **`ipAddress` is the TCP peer.** Behind a CDN or an upstream proxy you
  fingerprint that intermediary, not the client, and there is no
  `X-Forwarded-For` path here as there is for scoring.
- **HTTP/2 changes what header order means.** Ordering under HPACK is an
  artifact of the encoder, not the client's own preference, and only the first
  stream on a connection reports the full shape.

The buffer also lives in the session table, which is not mirrored, so events
still buffered at a failover are lost. That is telemetry, not enforcement.

## What it does not do

This is a **context-only producer**. It never sends an `authentication` block,
so the Shield API routes these events to traffic-intelligence storage; they
never create scored IP documents and never affect an address's reputation. The
existing authentication path (`REPORT_AUTH_RESULT` in `MIDEYE_SHIELD_COMMON`)
is untouched and keeps its own per-event sideband.

## Buffering and failure

Events go through the shared event buffer in `MIDEYE_SHIELD_COMMON`
(`_ENQUEUE_EVENT_DEFERRED`, which buffers and leaves the POST to `_FLUSH_IF_DUE`
on close), in the iRule's own subtable `MIDEYE_SHIELD_TRAFFIC` so that it and
the blocked-event buffer cannot evict each other's keys. One sideband
POST per request would not survive contact with real traffic.

The buffer is bounded three ways, and every bound fails open:

| Bound | Setting | On reaching it |
|---|---|---|
| Batch size | `traffic_batch_size` | Flush |
| Flush interval | `traffic_flush_interval` | Flush from the first close once the oldest event has waited this long; from a request at twice it, if no close has come |
| Hard cap | `traffic_max_buffer` | Drop the event, count it, warn once per flush |

## Size

Those three bound how *many* events are held, never how large one is — and size
is the client's to choose, since header names come from the request and every
byte outside printable ASCII escapes to six. Unbounded, 16 kB of header names
(inside a default HTTP profile's own limits) inflates one event past 100 kB.

So three more bounds are in bytes:

| Bound | Where | On reaching it |
|---|---|---|
| Header block | `traffic_max_headers` (2048) | Stop adding names; the leading order is kept, which is where the fingerprint is |
| Whole event | `traffic_max_event` (8192) | Drop the event — later requests still report the slim shape, which carries the JA4 |
| POST body | `max_batch_bytes` (921600) | Take what fits, leave the rest for the next flush. Clears the 1 MB body limit an ingress commonly defaults to |

The buffer is priced by the same numbers: `traffic_max_buffer` events at up to
`traffic_max_event` bytes each, so the default 5000 reserves at most **40 MB**.
A subtable's entries all live on one processor, so that is 40 MB on a *single*
TMM — raising the cap to 100000 asks for up to 800 MB on one TMM. It is
deliberately not clamped; what a device spends on telemetry is the operator's
call.

Worst case is not typical. Measured against the real event builder, a Chrome
request costs 1175 bytes on a connection's first request and 309 on later ones,
so a 4:1 mix averages **482 bytes** — a 472 kB POST body at the default batch
size, and about 2.4 MB resident at the cap. The 8 kB ceiling is what an attacker
choosing their own header names can force, not what ordinary traffic costs.
`tests/test_event_bounds.tcl` measures the worst case as well as asserting the
caps.

No failure here can block a request, alter it, or fail a deployment.

## When the batch is sent

The HSSR sideband call is **synchronous**: whichever iRule event flushes waits
for it. So the flush happens in `CLIENT_CLOSED`, on a connection that has already
finished, rather than on the request that filled the batch. Every closing
connection checks — that is what drains the last partial batch when traffic goes
quiet — and the check is two table lookups that return immediately on an empty
buffer.

`_FLUSH_IF_DUE` in `MIDEYE_SHIELD_COMMON` is the only definition of *due*; the
inline path routes through it too, so the two cannot drift apart. Block reporting
still flushes inline, from an event already deciding the connection's fate.

*Due* is measured from the oldest buffered event, not from the last flush: the
first close after the interval takes whatever a burst left behind. A clock reset
by every flush let that tail expire instead — at the default interval, a burst
of 20 requests followed by silence delivered 1.

`CLIENT_CLOSED` reads nothing connection-scoped. The known TMM defects here are
an iRule resuming into a flow that is already gone, and the session table
outlives the flow. `tests/test_deferred_flush.tcl` asserts that against the iRule
source.

A reachable API answers in tens of milliseconds; an unreachable one costs up to
the configured **API Timeout** (2500 ms), after which flushing pauses for
`api_retry_after` seconds. On a busy Virtual Server the cost lands on a finished
connection. On a quiet one the aged-tail backstop below can land it on a
request: while the API is down, at most one request per pause waits out the
timeout. Raising `traffic_batch_size` makes flushes rarer, not shorter.

### The backstops

Deferring fails in two ways — landing too slowly, or not at all — and each has a
backstop that makes the buffering caller flush inline instead. Both cost what the
inline path has always cost. On a busy Virtual Server a close reaches the batch
first, so neither normally fires; neither fires at all while flushing is paused.

| Backstop | Trigger | Why |
|---|---|---|
| Backlog | Twice `traffic_batch_size`, or half `traffic_max_buffer`, whichever is lower | Twice, so a deferring caller can pass the batch size and still wait for a close. Half the cap, so raising the cap cannot push the backstop out of reach |
| Aged tail | The oldest buffered event is twice `traffic_flush_interval` old | The close path takes the buffer at one interval, so an event still waiting at two has no close coming: keep-alives, websockets, one HTTP/2 connection carrying a session |

An event lives `2T + 360` seconds: past the backstop above, and long enough for
a keep-alive connection to reach the TCP profile's default idle timeout and
close. An expired event is reported: `_FLUSH_EVENTS` counts the empty slots it skips and
warns, so silence means no loss rather than unmeasured loss.

## Fingerprints

**JA3** (Salesforce) is `MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,
ECPointFormats)`. The values are decimal, joined with `-`, GREASE removed,
original order preserved — JA3 does not sort. It keys on the legacy
`client_version` field.

**JA4** (FoxIO) is `ja4_a_ja4_b_ja4_c`, where `a` encodes transport, TLS
version, SNI presence, cipher and extension counts and the ALPN 2-character
code; `b` is a truncated SHA-256 of the sorted ciphers; and `c` is a truncated
SHA-256 of the sorted extensions (excluding SNI and ALPN) with the signature
algorithms in their original order. It takes its version from the
`supported_versions` extension when present.

The two therefore key on different fields, which is why the same ClientHello
offered with a TLS 1.0 legacy version moves its JA3 and leaves its JA4 alone.
GREASE values (RFC 8701) are stripped everywhere they can appear: cipher
suites, extension types, supported groups, signature algorithms and
supported versions.

`tests/test_parser_sanity.tcl` pins the JA4 against FoxIO's published vector for
a known ClientHello, which is what makes it a check of the spec rather than of
ourselves. No published JA3 exists for that hello, so the JA3 assertion is our
own recorded output: it catches drift, it cannot tell us the method was read
right. Both are labelled as such in the test.

### Licensing

The ClientHello parsing is adapted from
[f5devcentral/f5-ja4](https://github.com/f5devcentral/f5-ja4) and redistributed
under BSD 3-Clause; the notice is carried in the iRule itself and in
[THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md). JA3 is reimplemented from
Salesforce's published method rather than copied. The JA4+ variants (JA4H,
JA4S, JA4L and the rest) are under the separate FoxIO License 1.1 and are not
implemented here.
