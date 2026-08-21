# Mideye Shield iApp for F5 BIG-IP

An iApp template that puts [Mideye Shield](https://www.mideye.com/) IP
reputation in front of a BIG-IP Virtual Server. It scores the connecting
address against the Shield API and denies, warns or allows before the
application ever sees the connection, and it can report authentication
outcomes back so future scoring improves.

Everything is packaged as a single importable template,
[`iApp/MIDEYE_SHIELD.tmpl`](iApp/MIDEYE_SHIELD.tmpl), generated from the iRule
sources in this repository.

## What it does

| iRule | Attach it to | What it does |
|---|---|---|
| `MIDEYE_SHIELD_CONNECTION` | any Virtual Server to protect | Scores the client IP at `CLIENT_ACCEPTED`, before any application data is exchanged, and rejects there. |
| `MIDEYE_SHIELD_APM` | an APM Virtual Server | Gates an access policy on the IP score before credentials are processed, and reports the authentication outcome back to Shield. |
| `MIDEYE_SHIELD_TRAFFIC` | a TLS or HTTP Virtual Server to fingerprint | Reports JA3/JA4 TLS client fingerprints and request metadata for **all** traffic, not just authentication attempts. On by default, wherever you attach it. |
| `MIDEYE_SHIELD_COMMON` | — | Shared library: scoring, caching, the API client, logging. Every setting lives in its `RULE_INIT`. |

Outbound calls to the Shield API go over HSSR, the sideband requester bundled
in `HSSR/`.

## Requirements

- BIG-IP 17.1 or later — 14.x, 15.1 and 16.1 have all reached F5 End of
  Technical Support, and 17.1 is the oldest branch F5 still supports
- Shield API credentials (client ID and secret) from Mideye
- Outbound HTTPS to the Shield API, and a DNS resolver the BIG-IP can use

## Installing

1. Get the template — download `iApp/MIDEYE_SHIELD.tmpl` from this repository,
   or take the artifact from a run of the **Build iApp template** workflow.
2. On the BIG-IP: **iApps ›› Templates ›› Import**, select the file.
3. **iApps ›› Application Services ›› Create**, choose the `MIDEYE_SHIELD`
   template, and fill in at least the API base URL, client ID and secret.
4. Attach `MIDEYE_SHIELD_CONNECTION` (and `MIDEYE_SHIELD_APM` for APM virtual
   servers) to the Virtual Servers you want protected, and
   `MIDEYE_SHIELD_TRAFFIC` to those you want fingerprinted.

Installation is deliberately manual. Nothing here deploys to a BIG-IP, so the
path this repository exercises is the same one a customer follows.

### Traffic intelligence

`MIDEYE_SHIELD_TRAFFIC` is **on by default** and reports on every connection to
the Virtual Servers you attach it to, not only on authentication attempts.
Deploying the template does not attach it anywhere, so attaching it is what
starts reporting.

List it **after** `MIDEYE_SHIELD_CONNECTION` when both are on the same Virtual
Server, so the enforcement decision completes first.

Attach it only where the **client speaks first** — TLS, and HTTP over it.
Capturing the handshake holds the server-side connection back until the client
sends, which hangs any protocol whose server greets first (SSH, SMTP, FTP,
MySQL). It is not safe on a general-purpose TCP Virtual Server.

[docs/traffic-intelligence.md](docs/traffic-intelligence.md) lists everything
that leaves the device. Read it before attaching the iRule.

## Building the template

`iApp/MIDEYE_SHIELD.tmpl` is generated, and committed so that it can be
imported without a build step. CI fails if it drifts from its sources, so
regenerate and commit it whenever an iRule or a setting changes:

```sh
make                    # prompts for the new version
make VERSION=1.2.0      # or stamp one non-interactively
```

The generator validates as it builds: unbalanced braces, statics with no
matching form field, and lines whose quoting would break tmsh's parser on
import all fail the build rather than the deployment.

## Developing

```sh
make test                  # the Tcl test suite
make mutate                # break one behaviour at a time, require a failure
bash tools/lint-irules.sh  # reject Tcl that TMM cannot run
```

Two things are worth knowing before changing an iRule:

**TMM's Tcl is 8.4-era.** No `dict`, `lassign`, `{*}`, `try` or `puts`. A
desktop `tclsh` is 8.6 and runs all of them happily, so neither the tests nor
review catches this — only the BIG-IP does, at iRule load time, after the
template is already on the box. `tools/lint-irules.sh` moves that failure into
CI.

**The tests are guarded by mutation testing.** `make test` passing says nothing
about assertions that cannot fail; `make mutate` breaks a specific behaviour
and requires the suite to notice. It also fails when a mutation's anchor text
no longer matches, so a refactor cannot silently leave it checking nothing.

## Layout

```
iApp/MIDEYE_SHIELD.tmpl   the generated template - import this
iApp/builder/             generator, settings (the iApp form), base template
iRules/                   iRule sources
HSSR/                     bundled sideband requester
tests/                    Tcl tests, run against the iRule sources
tools/                    lint and mutation checks
docs/                     feature documentation
```

## Licensing

The JA4 client fingerprinting in `MIDEYE_SHIELD_TRAFFIC` is adapted from
third-party BSD 3-Clause code. See
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
