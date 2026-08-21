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
- **Three header values**, each capped at 255 characters (User-Agent at 4095):
  - `User-Agent` — the client identity the feature exists to record.
  - `Host` — the same string already leaves as `destination.application.id`.
  - `Accept-Language` — names languages, not a person.
- **The request method**, and **the path without its query string**, capped at
  1023 characters.
- **This device's hostname**, as the sensor id, unless the iApp sets one.

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

## What it does not do

This is a **context-only producer**. It never sends an `authentication` block,
so the Shield API routes these events to traffic-intelligence storage; they
never create scored IP documents and never affect an address's reputation. The
existing authentication path (`REPORT_AUTH_RESULT` in `MIDEYE_SHIELD_COMMON`)
is untouched and keeps its own per-event sideband.

## Buffering and failure

Events go through the shared event buffer in `MIDEYE_SHIELD_COMMON`
(`_ENQUEUE_EVENT`), in the iRule's own subtable `MIDEYE_SHIELD_TRAFFIC` so that
it and the blocked-event buffer cannot evict each other's keys. One sideband
POST per request would not survive contact with real traffic.

The buffer is bounded three ways, and every bound fails open:

| Bound | Setting | On reaching it |
|---|---|---|
| Batch size | `traffic_batch_size` | Flush |
| Flush interval | `traffic_flush_interval` | Flush on the next event |
| Hard cap | `traffic_max_buffer` | Drop the event, count it, warn once per flush |

## Size

Those three bound how *many* events are held, never how large one is, and the
size is not ours to choose: header names come from the client, and every byte
outside printable ASCII is escaped to six characters so a batch cannot be
broken by one bad byte. Unbounded, 16 kB of header names — inside a default
HTTP profile's own `max-header-count` 64 and `max-header-size` 32768 — inflates
one event past 100 kB, and a full buffer past 100 MB in a single POST.

So two bounds are in bytes, in `MIDEYE_SHIELD_TRAFFIC`'s `RULE_INIT`:

| Bound | Static | On reaching it |
|---|---|---|
| Header block | `traffic_max_headers` (2048) | Stop adding names; the leading order is kept, which is where the fingerprint is |
| Whole event | `traffic_max_event` (8192) | Drop the event |

An event is dropped rather than trimmed, so nobody gets to choose the size of
what they send us. The connection is not lost with it: every later request
reports the slim shape, which still carries the JA4, so the client stays
identified. With the 1000-event cap in `_FLUSH_EVENTS`, one POST body cannot
exceed 8 MB.

The same two numbers price the buffer itself: `traffic_max_buffer` events of at
most `traffic_max_event` bytes each, so the default cap of 5000 reserves at
most **40 MB per TMM**. The cap is an amount of memory as much as a count of
events, and nothing else bounds it — raising it to 100000 is asking for up to
800 MB on every TMM. It is deliberately not clamped: what a device can afford
to spend on telemetry is the operator's call, not this iRule's.

Worst case is not typical. Measured against the real event builder, a Chrome
request reports 1175 bytes on a connection's first request and 309 on every
later one, so a realistic 4:1 mix averages **482 bytes**. At the default batch
size that is a **472 kB** POST body and about 2.4 MB resident at the cap. The
8 kB ceiling is what an attacker choosing their own header names can force, not
what ordinary traffic costs.

`tests/test_event_bounds.tcl` measures this against the worst input the code
can be handed — every field at its cap, every byte a six-character escape —
rather than asserting the caps exist.

Losing telemetry is always preferable to changing what happens to a connection.
No failure here can block a request, alter it, or fail a deployment.

## When the batch is sent

`_FLUSH_EVENTS` POSTs over HSSR, and that sideband call is **synchronous** —
whichever iRule event performs the flush waits for it. So the flush is not done
by the request that filled the batch. It happens in `CLIENT_CLOSED`, on a
connection that has already finished, where nobody is waiting for a response.

Every closing connection checks, not only one that reported something. That is
what drains the last partial batch once traffic goes quiet, and the check is two
table lookups that return immediately when the buffer is empty.

The check itself is `_FLUSH_IF_DUE` in `MIDEYE_SHIELD_COMMON`, which is the only
definition of *due* — the inline path routes through it too, so the two cannot
drift apart. Block reporting still flushes inline: it is raised from an event
already deciding the connection's fate, so there is no cheaper moment for it.

`CLIENT_CLOSED` reads nothing connection-scoped, before or after the flush. The
known TMM defects in this area are all an iRule resuming into a flow that is
already gone; the session table outlives the flow, and nothing else is touched.
`tests/test_deferred_flush.tcl` asserts that against the iRule source, so a
later edit reaching for the client address fails there rather than in
production.

### The backstops

Deferred flushes land on connection close, so there are two ways for them to
fail: landing too slowly, or not landing at all. Each has a backstop, and both
work by having the buffering caller stop deferring and flush inline.

**A backlog.** If closes cannot keep up — a TMOS that declines to suspend a
close event — the buffer would fill to `traffic_max_buffer` and start dropping.
The trigger is twice `traffic_batch_size`, or half the cap, whichever is lower.
Twice, because a deferring caller is meant to let the buffer pass the batch size
and wait for a close — trigger at the batch size itself and it would flush from
the request every time, which is the cost deferring exists to avoid. Half the
cap, because how much an operator is willing to buffer says nothing about
whether closes are landing, so raising the cap must not push the backstop out
of reach.

**A lapsed flush interval.** If closes are simply rarer than
`traffic_flush_interval`, buffered events reach their TTL of `2T + 60` seconds
and expire where they sit: sent nowhere, and counted as no drop. That is not an
exotic shape — keep-alive connections, websockets and any quiet Virtual Server
have it, and the quieter the traffic the more of it is lost.

Both cost exactly what the inline path has always cost, and neither can fire on
a busy Virtual Server, where closes keep the last flush recent. The deferral
holds precisely where the wait was worth moving.

### What it costs

A reachable API answers a flush in tens of milliseconds; an unreachable one
costs up to the configured **API Timeout** (2500 ms). Either way the cost lands
on a finished connection rather than a live request. Raising
`traffic_batch_size` makes flushes rarer, not shorter.

The same fail-open principle applies to parsing: a ClientHello that does not
parse — fragmented across TLS records, or contradicting its own length fields —
is dropped rather than guessed at, because a confident wrong fingerprint is
worse than no fingerprint. Scale is the one exception: a hello offering more
than 256 ciphers, extensions or vector entries has that list truncated at the
bound instead of being rejected.

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

`tests/test_parser_sanity.tcl` pins both against published vectors for a known
ClientHello. That is the point of those assertions: a test that only pins our
own output cannot tell us we are wrong.

### Licensing

The ClientHello parsing is adapted from
[f5devcentral/f5-ja4](https://github.com/f5devcentral/f5-ja4) and redistributed
under BSD 3-Clause; the notice is carried in the iRule itself and in
[THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md). JA3 is reimplemented from
Salesforce's published method rather than copied. The JA4+ variants (JA4H,
JA4S, JA4L and the rest) are under the separate FoxIO License 1.1 and are not
implemented here.
