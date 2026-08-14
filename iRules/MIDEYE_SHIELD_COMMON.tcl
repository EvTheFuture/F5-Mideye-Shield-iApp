# =============================================================================
# iRule   : MIDEYE_SHIELD_COMMON
# Version : 0.9.18
# Author  : Magnus Sandin, Valitron AB
# Date    : 2026-08-14
#
# Purpose
# -------
# This iRule acts as the shared library for the Mideye Shield integration.
# It exposes procedures that are called from the other Shield iRules via
# the "call" command. No traffic events are handled here directly.
#
# This iRule does NOT need to be attached to any Virtual Server.
#
# All API communication, token lifecycle management, IP score caching, black-
# and whitelist evaluation, and statistics counter maintenance live here so
# that the calling iRules stay thin and policy-free.
#
#
# Configuration
# -------------
# All settings are stored as TCL static variables in the "static::" namespace
# with a "MIDEYE_SHIELD_" prefix. They are initialised in the RULE_INIT event
# below using __PLACEHOLDER__ tokens that the iApp template substitutes with
# values supplied by the administrator at iApp deployment time.
#
# Static variables are shared across all iRules on the same TMM, so the values
# defined here are available to MIDEYE_SHIELD_APM, MIDEYE_SHIELD_CONNECTION,
# and any future Shield iRule via plain $static::MIDEYE_SHIELD_<key> reads.
#
#
# Description
# -----------
# Procs are called from other iRules using the full iRule path syntax:
#   call /__partition__/MIDEYE_SHIELD_COMMON::<PROCNAME> <args>
#
# The statistics, cache and token procs hardcode the subtable name
# "MIDEYE_SHIELD" rather than holding it in a variable. The event buffer procs
# take their subtable as a parameter instead, so each caller owns an
# independent buffer.
#
# The token_fetching sentinel uses "table add" (-excl semantics) rather than
# incr, because it is a binary lock, not a counter. "table add" only writes if
# the key does not already exist, which gives a single atomic test-and-set with
# no read-modify-write gap. What it hands back when it declines is not specified
# firmly enough to bet on, so a lock whose holder must be identified exactly -
# the event flush lock - claims a unique ticket and reads the key back instead.
#
#
# Session Variables
# -----------------
# session.custom.shield.method        - Store ONE of the following values during authentication
#                                       -------------------------------------------------------
#                                       client_certificate
#                                       password_only
#                                       password_totp
#                                       passwordless_eid
#
# session.custom.shield.reason        - Store ONE of the following authentication results
#                                       -------------------------------------------------
#                                       success
#                                       failed_second_factor
#                                       invalid_password
#                                       user_not_found
#
# iRule Events
# ------------
# MIDEYE_SHIELD-VALIDATE_IP         - Call this to validate the connecting client's IP address
#                                     Use the following branch rule to branch if the IP is Allowed
#                                     "expr {[mcget session.custom.shield.allow] == 1}"
#
# MIDEYE_SHIELD-REPORT_AUTH_RESULT  - Call this to report the authentication outcome outcome
#
# Procedures exposed
# ------------------
#   /__partition__/MIDEYE_SHIELD_COMMON::LOG_ALERT
#       Log to syslog with severity Alert
#
#   /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG
#       Log to syslog with severity Debug (if debug is enabled in iApp settings)
#
#   /__partition__/MIDEYE_SHIELD_COMMON::LOG_ERROR
#       Log to syslog with severity Error
#
#   /__partition__/MIDEYE_SHIELD_COMMON::LOG_INFO
#       Log to syslog with severity Info
#
#   /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING
#       Log to syslog with severity Warn
#
#   /__partition__/MIDEYE_SHIELD_COMMON::GET_STATS
#       Returns a flat {key value key value ...} list of all counters.
#       Iterate with: foreach {K V} [call /__partition__/MIDEYE_SHIELD_COMMON::GET_STATS] {}
#
#   /__partition__/MIDEYE_SHIELD_COMMON::REPORT_AUTH_RESULT  client_ip
#       Fire-and-forget report of an auth outcome back to the Shield API.
#       Called from the APM iRule after ACCESS_POLICY_COMPLETED and ACCESS_SESSION_CLOSED.
#
#   /__partition__/MIDEYE_SHIELD_COMMON::RESET_STATS
#       Resets all statistics counters to zero.
#
#   /__partition__/MIDEYE_SHIELD_COMMON::VALIDATE_CONNECTION  client_ip
#       Validates an IP at the TCP connection level using score_cache_time.
#       Returns 1 to allow, 0 to reject.
#       All logging and counter updates are handled internally.
#       In dry_run mode always returns 1 but logs what would have been denied.
#
#   /__partition__/MIDEYE_SHIELD_COMMON::VALIDATE_LOGIN  client_ip
#       Validates an IP at the login/APM level using login_score_cache_time.
#       Returns 1 to allow, 0 to reject.
#       Otherwise identical behaviour to VALIDATE_CONNECTION.
#       Use this when a shorter cache time is appropriate, e.g. before
#       authenticating a user where a fresher score is desirable.
#
#
# Dependencies - Data Groups
# --------------------------
# Settings are no longer stored in a Data Group. They are configured via the
# Mideye Shield iApp and injected into RULE_INIT below.
#
#   MIDEYE_SHIELD_WHITELIST  (address type, supports CIDR)
#       IP addresses and networks that bypass Shield checks entirely.
#       Example entry: 192.168.0.0/16
#
#   MIDEYE_SHIELD_BLACKLIST  (address type, supports CIDR)
#       IP addresses and networks that are always denied immediately.
#       Example entry: 10.0.0.0/8
#
#
# Dependencies - iRules (call targets)
# -------------------------------------
#   HSSR  (HTTP Super Sideband Requester)
#       Called via:
#           call __hssr_irule__::http_req -uri <url> -virt <helper> [options]
#       Returns the HTTP status code as an integer.
#       Response body is received into a named variable via -rbody.
#       Key options used in this iRule:
#           -method   GET|POST
#           -uri      full URL including path
#           -headers  flat alternating list of header name/value pairs
#           -body     request body string
#           -type     Content-Type header value for -body
#           -timeout  connection timeout in milliseconds
#           -virt     helper virtual server path (from hssr-helper-vs setting)
#           -rbody    name of variable to receive response body (no $ prefix)
#
#
# Dependencies - Session Table (subtable)
# ----------------------------------------
# Statistics, cache and token keys live in the subtable "MIDEYE_SHIELD"; the
# blocked-event buffer keeps its own subtable, "MIDEYE_SHIELD_BLOCKS", so a
# flood of one kind of key cannot evict the other's. Key naming conventions
# used internally in "MIDEYE_SHIELD":
#
#   score_<ip>            - Cached score for an IP (-1 = under investigation)
#   pending_<ip>          - Number of connections waiting for this IP's score
#   token                 - Cached API access token string
#   token_fetching        - Binary lock: present means a fetch is in progress
#   api_down              - Sentinel: 1 means API is currently considered down
#   stat_requests         - Counter: total incoming connections evaluated
#   stat_blacklisted      - Counter: blacklist hits
#   stat_whitelisted      - Counter: whitelist hits
#   stat_cache_hits       - Counter: score served from cache
#   stat_cache_misses     - Counter: score not in cache, API was needed
#   stat_api_success      - Counter: successful API score lookups
#   stat_api_fail         - Counter: failed API score lookups
#   stat_allowed_apifail  - Counter: connections allowed due to API failure
#   stat_allowed_score    - Counter: connections allowed due to acceptable score
#   stat_blocked          - Counter: connections blocked
#
# And in "MIDEYE_SHIELD_BLOCKS", written only by the event buffer procs:
#
#   seq                   - Sequence number of the last event enqueued
#   cursor                - Sequence number of the last event flushed
#   evt_<n>               - Buffered event body (JSON), keyed by sequence number
#   flush_lock            - Ticket of the flusher currently holding the lock
#   ticket                - Counter handing out unique flush-lock tickets
#   last_flush            - Epoch seconds of the last completed flush
#   dropped               - Counter: events discarded since the last flush
#
# =============================================================================

when RULE_INIT {
    # All Mideye Shield configuration settings are defined here as TCL static
    # variables in the "static::" namespace, with prefix "MIDEYE_SHIELD_" to
    # avoid collisions with any other iApp / iRule on the system.
    #
    # The __PLACEHOLDER__ tokens below are substituted by the Mideye Shield
    # iApp implementation block at deployment time with values entered by the
    # administrator in the iApp presentation form.
    #
    # NOTE: The iApp template generator script scans this block to discover
    # which settings exist. Every variable declared here MUST have a matching
    # entry in the iApp settings json (variables/labels/presentation) or the
    # generator will emit a warning.

    # API Settings
    set static::MIDEYE_SHIELD_log_debug              "__log__debug__"

    # API Settings
    set static::MIDEYE_SHIELD_api_base_url           "__api__base_url__"
    set static::MIDEYE_SHIELD_api_client_id          "__api__client_id__"
    set static::MIDEYE_SHIELD_api_client_secret      "__api__client_secret__"
    set static::MIDEYE_SHIELD_api_scope              "__api__scope__"
    set static::MIDEYE_SHIELD_api_token_url          "__api__token_url__"
    set static::MIDEYE_SHIELD_api_timeout            "__api__timeout__"
    set static::MIDEYE_SHIELD_api_token_safeguard    "__api__token_safeguard__"
    set static::MIDEYE_SHIELD_api_down_cache_time    "__api__down_cache_time__"
    set static::MIDEYE_SHIELD_api_retry_after        "__api__retry_after__"

    # Behaviour flags
    set static::MIDEYE_SHIELD_disabled               "__behaviour__disabled__"
    set static::MIDEYE_SHIELD_dry_run                "__behaviour__dry_run__"

    # Score thresholds and cache TTLs
    set static::MIDEYE_SHIELD_score_hard_deny        "__score__hard_deny__"
    set static::MIDEYE_SHIELD_score_warn             "__score__warn__"
    set static::MIDEYE_SHIELD_score_cache_time       "__score__cache_time__"
    set static::MIDEYE_SHIELD_login_score_cache_time "__score__login_cache_time__"
    set static::MIDEYE_SHIELD_score_deny_cache_time  "__score__deny_cache_time__"

    # Pending queue and polling
    set static::MIDEYE_SHIELD_pending_max            "__pending__max__"
    set static::MIDEYE_SHIELD_pending_poll_interval  "__pending__poll_interval__"

    # Infrastructure
    set static::MIDEYE_SHIELD_dns                    "__infra__dns__"
    set static::MIDEYE_SHIELD_hssr_helper_vs         "__hssr_helper_vs__"

    # Hashing
    set static::MIDEYE_SHIELD_username_salt          "__hash__username_salt__"

    # Blocked-event reporting buffer. Separate from any other buffer so one
    # flood cannot evict the other's events.
    set static::MIDEYE_SHIELD_block_enabled        "__block__enabled__"
    set static::MIDEYE_SHIELD_block_batch_size     "__block__batch_size__"
    set static::MIDEYE_SHIELD_block_flush_interval "__block__flush_interval__"
    set static::MIDEYE_SHIELD_block_max_buffer     "__block__max_buffer__"

    # Escape map for JSON string values, built once here rather than per call.
    #
    # Every byte outside printable ASCII is escaped, not just the C0 controls: a
    # single byte that is not valid UTF-8 makes the whole batch POST unparseable,
    # dropping every other event buffered with it. \u00xx keeps the byte value
    # and is always valid JSON.
    #
    # Not an iApp setting: the generator's cross-check only matches statics whose
    # value is a double-quoted string, so this list is invisible to it.
    set static::MIDEYE_SHIELD_json_map [list \\ \\\\ \" \\\" \n \\n \r \\r \t \\t \b \\b \f \\f]
    for { set c 0 } { $c < 256 } { incr c } {
        if { $c >= 0x20 && $c < 0x7f } { continue }
        if { $c == 8 || $c == 9 || $c == 10 || $c == 12 || $c == 13 } { continue }
        lappend static::MIDEYE_SHIELD_json_map \
            [format %c $c] [format {\u%04x} $c]
    }
}

# ===========================================================================
# P R I V A T E   P R O C E D U R E S
# ===========================================================================

# ---------------------------------------------------------------------------
# proc: _JSON_ESCAPE
#
# Escape a string for inclusion in a JSON double-quoted value, using the map
# built in RULE_INIT (see there for why non-ASCII is escaped too).
# ---------------------------------------------------------------------------
proc _JSON_ESCAPE { s } {
    return [string map $static::MIDEYE_SHIELD_json_map $s]
}

# ---------------------------------------------------------------------------
# proc: _ENQUEUE_EVENT
#
# Append one event (JSON string) to the buffer in subtable "sub". Drops the
# event (fail-open, counted) when the buffer is at capacity. Triggers a flush
# when the buffer reaches batch_size OR flush_interval has elapsed since the
# last flush (the time trigger fires on the next event after T - a truly idle
# buffer self-expires via the per-event TTL).
#
# Sizing arrives as arguments rather than statics so each caller owns its own
# buffer settings and its own subtable.
# ---------------------------------------------------------------------------
proc _ENQUEUE_EVENT { sub event_json batch_size flush_interval max_buffer } {
    set N      $batch_size
    set T      $flush_interval
    set MAXBUF $max_buffer

    # These come from free-text iApp fields. Tcl compares a non-numeric operand
    # as a string rather than failing, so a typo like "1,000" would quietly make
    # every comparison below meaningless; fall back to the defaults instead of
    # reporting nothing at all.
    if { ![string is integer -strict $N]      || $N < 1 }      { set N 200 }
    if { ![string is integer -strict $T]      || $T < 1 }      { set T 10 }
    if { ![string is integer -strict $MAXBUF] || $MAXBUF < 1 } { set MAXBUF 1000 }

    # A batch size above the cap can never be reached: events are dropped at the
    # cap long before the batch fills, leaving the timer as the only trigger.
    if { $N > $MAXBUF } { set N $MAXBUF }

    # An event has to outlive the interval it is waiting for. Deriving the TTL
    # from T rather than fixing it means raising the flush interval cannot
    # silently expire the very buffer that interval exists to accumulate.
    set TTL [expr { $T * 2 + 60 }]

    # Seed with `table add` rather than pinning after the fact: `table incr`
    # then `table set ... 1` loses an increment when two callers race at cold
    # start, and two events then claim the same sequence number.
    table add -subtable $sub "seq" 0 indefinite indefinite
    set seq [table incr -subtable $sub "seq"]

    set cursor [table lookup -subtable $sub "cursor"]
    if { $cursor eq "" } { set cursor 0 }
    set buffered [expr { $seq - $cursor }]

    # Over capacity: drop this event, but still fall through to the flush
    # trigger below. Returning here would be terminal - the cursor only ever
    # advances in _FLUSH_EVENTS, so skipping the trigger leaves nothing that can
    # ever bring the buffer back under the cap.
    if { $buffered > $MAXBUF } {
        # Seeded like seq and ticket: created by incr alone it inherits the
        # subtable's default timeout and can expire between infrequent flushes,
        # undercounting exactly when the buffer is in trouble.
        table add -subtable $sub "dropped" 0 indefinite indefinite
        table incr -subtable $sub "dropped"
    } else {
        table set -subtable $sub "evt_$seq" $event_json $TTL $TTL
    }

    set last [table lookup -subtable $sub "last_flush"]
    if { $last eq "" } { set last 0 }

    if { $buffered >= $N || ([clock seconds] - $last) >= $T } {
        call /__partition__/MIDEYE_SHIELD_COMMON::_FLUSH_EVENTS $sub
    }
}

# ---------------------------------------------------------------------------
# proc: _RELEASE_FLUSH_LOCK
#
# Release the flush lock only if we still hold it. A flush that overran its lock
# TTL has already been replaced by another flusher; deleting the entry then
# would free THEIR lock and let a third run alongside them.
# ---------------------------------------------------------------------------
proc _RELEASE_FLUSH_LOCK { sub tok } {
    if { [table lookup -subtable $sub "flush_lock"] eq $tok } {
        table delete -subtable $sub "flush_lock"
    }
}

# ---------------------------------------------------------------------------
# proc: _FLUSH_EVENTS
#
# Gather up to 1000 buffered events (the Shield API per-request cap) into one
# {"events":[...]} body and POST it once over HSSR.
#
# A ticket lock serialises flushers within one TMM, not device-wide: the session
# table is per-TMM, so an N-TMM box holds N independent buffers and can have N
# flushes in flight at once, and the real ceiling is max_buffer * N.
#
# Fire-and-forget: a failed POST drops that batch rather than retrying, keeping
# the buffer bounded - but it says so out loud, because by then the events are
# gone. A flush with no API token is the one exception: it gives up before
# consuming anything, so the batch outlives the outage.
# ---------------------------------------------------------------------------
proc _FLUSH_EVENTS { sub } {
    # Set only by the token-outage path below, which is the one exit that leaves
    # last_flush untouched: without this gate the timer stays permanently due
    # and every buffered event costs another doomed token request. Those share
    # the sideband path with score lookups, so an outage would degrade the
    # blocking itself - a reporting failure must not reach that far.
    if { [table lookup -subtable $sub "backoff"] ne "" } { return }

    set TIMEOUT $static::MIDEYE_SHIELD_api_timeout

    # From a free-text iApp field. A non-numeric value would throw out of the
    # expr below, which sits outside this proc's catch, aborting the caller's
    # iRule event - fail-closed, in a fail-open feature.
    if { ![string is integer -strict $TIMEOUT] || $TIMEOUT < 1 } { set TIMEOUT 2500 }

    set LOCK_TTL [expr { int($TIMEOUT / 1000) + 5 }]

    # Cold-start race: `table incr` then `table set ... 1` loses an increment
    # when two flushers arrive together, and a duplicated ticket lets both hold
    # the lock at once and POST the same events twice. Seeding with `table add`
    # establishes the indefinite lifetime before any increment.
    table add -subtable $sub "ticket" 0 indefinite indefinite
    set tok [table incr -subtable $sub "ticket"]

    # `table add` will not overwrite an existing entry, but what it returns is
    # not specified firmly enough to bet a lock on - in either direction. Claim
    # a ticket no other flusher can hold, then read the lock back: only the
    # holder sees its own ticket, whatever add returned.
    table add -subtable $sub "flush_lock" $tok $LOCK_TTL $LOCK_TTL
    if { [table lookup -subtable $sub "flush_lock"] ne $tok } {
        return
    }

    # Fetched before the batch is consumed. Everything below destroys the events
    # whatever happens next, so a token outage must not reach it: with no token
    # there is no request to attempt, and burning the buffer for nothing loses
    # 100% of blocks for the whole outage. Leave the cursor, the events,
    # last_flush and dropped untouched and let the next flush try again.
    set TOKEN ""
    if { [catch { set TOKEN [call /__partition__/MIDEYE_SHIELD_COMMON::_GET_VALID_TOKEN] } token_err] } {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "$sub: token lookup failed -> $token_err"
        set TOKEN ""
    }

    if { $TOKEN eq "" } {
        set RETRY $static::MIDEYE_SHIELD_api_retry_after

        # Free-text iApp field, as with the buffer settings above.
        if { ![string is integer -strict $RETRY] || $RETRY < 1 } { set RETRY 30 }

        # Deliberately not _MARK_API_DOWN: that is the score path's breaker, and
        # failing to report must never make the iApp stop scoring. The backoff
        # is per-buffer and only ever suppresses reporting.
        table set -subtable $sub "backoff" 1 $RETRY $RETRY

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "$sub: no valid API token, keeping buffered event(s) and backing off ${RETRY}s"
        call /__partition__/MIDEYE_SHIELD_COMMON::_RELEASE_FLUSH_LOCK $sub $tok
        return
    }

    set cursor [table lookup -subtable $sub "cursor"]
    if { $cursor eq "" } { set cursor 0 }
    set seq [table lookup -subtable $sub "seq"]
    if { $seq eq "" } { set seq 0 }

    set end $seq
    if { [expr { $end - $cursor }] > 1000 } {
        set end [expr { $cursor + 1000 }]
    }

    # A missing entry is either an event dropped at the cap or one whose sequence
    # number is already claimed but whose body has not landed yet; from here the
    # two look identical. Both are skipped rather than waited for - stopping at a
    # gap would wedge the cursor permanently the first time an entry expired.
    set events [list]
    for { set s [expr { $cursor + 1 }] } { $s <= $end } { incr s } {
        set j [table lookup -subtable $sub "evt_$s"]
        if { $j ne "" } {
            lappend events $j
            table delete -subtable $sub "evt_$s"
        }
    }

    table set -subtable $sub "cursor" $end indefinite indefinite
    table set -subtable $sub "last_flush" [clock seconds] indefinite indefinite

    # Report overflow here rather than leaving it in a table key nothing reads.
    # Once per flush is rate-limited by construction, and a buffer that is
    # dropping events is the one thing an operator needs to be told.
    set dropped [table lookup -subtable $sub "dropped"]
    if { $dropped ne "" && $dropped > 0 } {
        table delete -subtable $sub "dropped"
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "$sub: buffer full, dropped $dropped event(s) since the last flush"
    }

    if { [llength $events] == 0 } {
        call /__partition__/MIDEYE_SHIELD_COMMON::_RELEASE_FLUSH_LOCK $sub $tok
        return
    }

    set BODY "\{\"events\":\[[join $events ,]\]\}"

    call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "$sub: flushing [llength $events] event(s) to /ips/events"

    # The events are already deleted and the cursor already advanced, so this
    # batch is gone whatever happens next. Anything that goes wrong has to be
    # said out loud: a Shield API that rejects every POST is otherwise
    # indistinguishable from a healthy iApp seeing no traffic.
    set failure ""
    if { [catch {
        set BASE_URL $static::MIDEYE_SHIELD_api_base_url
        call /__partition__/MIDEYE_SHIELD_COMMON::_BUILD_HSSR_ARGS ARGS "POST" "${BASE_URL}/ips/events"
        lappend ARGS \
            -headers [list "Authorization" "Bearer ${TOKEN}"] \
            -body    $BODY \
            -type    "application/json"
        set STATUS [call __hssr_irule__::http_req $ARGS]
        if { $STATUS ne "" && ![string match "2*" $STATUS] } {
            set failure "HTTP $STATUS"
        }
    } err] } {
        set failure $err
    }

    if { $failure ne "" } {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "$sub: dropped [llength $events] event(s) -> $failure"
    }

    call /__partition__/MIDEYE_SHIELD_COMMON::_RELEASE_FLUSH_LOCK $sub $tok
}

# ---------------------------------------------------------------------------
# proc:_LOG_COMMON
#
# DO NOT USE, this is an INTERNAL PROCEDURE
#
#  level: debug, info, warning, error, alert
#    msg: Log message
# noname: true | false (if true, don't log iRule name)
#
# Returns void
# ---------------------------------------------------------------------------
proc _LOG_COMMON {level msg {noname false}} {
    set chunk_size 750

    if {$noname} {
        set prefix "MIDEYE_SHIELD: "
    } else {
        set prefix ""
    }

    set id ""

    catch {
        set sid [ACCESS::session data get session.user.display_sessionid]
        if {$sid != ""} {
            set id "${sid}: "
        }
    }

    if {$id == ""} {
        catch { set id "<[IP::client_addr]:[TCP::client_port]>: " } ERR
    }

    append prefix $id

    # Get the total length of the input string
    set len [string length $msg]

    # If the string is empty, do nothing
    if {$len == 0} {
        return
    }

    # Start position
    set start 0

    while {$start < $len} {
        # Calculate end position for this chunk
        set end [expr {$start + $chunk_size}]

        # Make sure we don't go beyond the string length
        if {$end > $len} {
            set end $len
        }

        # Extract the substring for this chunk
        set chunk [string range $msg $start [expr {$end - 1}]]

        if {$start == 0} {
            set msgtolog "$prefix$chunk"
        } else {
            set msgtolog "$chunk"
        }

        # Print the chunk
        # Possibility to add conditional debugging
        if {$noname} {
            log -noname local0.$level "$msgtolog"
        } else {
            log local0.$level "$msgtolog"
        }

        if {$prefix != ""} {
            catch {ACCESS::log accesscontrol.$level $chunk}
        }

        # Move to the next chunk
        set start $end
    }
}

# ---------------------------------------------------------------------------
# proc: _TBL_GET
#
# Read a value from the Shield subtable.
#
# Returns empty string if the key does not exist.
# ---------------------------------------------------------------------------
proc _TBL_GET { key } {
    return [table lookup -subtable "MIDEYE_SHIELD" $key]
}

# ---------------------------------------------------------------------------
# proc: _TBL_SET
#
# Write a value to the Shield subtable with a lifetime and idle timeout.
# Both lifetime and idle_timeout are in seconds.
#
# Pass "indefinite" for either argument to mean never expire.
# ---------------------------------------------------------------------------
proc _TBL_SET { key value lifetime idle_timeout } {
    table set -subtable "MIDEYE_SHIELD" $key $value $lifetime $idle_timeout
}

# ---------------------------------------------------------------------------
# proc: _TBL_DEL
#
# Delete a key from the Shield subtable.
# ---------------------------------------------------------------------------
proc _TBL_DEL { key } {
    table delete -subtable "MIDEYE_SHIELD" $key
}

# ---------------------------------------------------------------------------
# proc: _TBL_INCR
#
# Atomically increment a counter in the Shield subtable.
# On first creation (returns 1) the lifetime is set to indefinite so that
# counters survive across connections.
#
# Returns the new value after increment.
# ---------------------------------------------------------------------------
proc _TBL_INCR { key } {
    set VAL [table incr -subtable "MIDEYE_SHIELD" $key]

    if { $VAL == 1 } {
        # First time this counter is created - pin it so it never expires.
        table set -subtable "MIDEYE_SHIELD" $key 1 indefinite indefinite
    }

    return $VAL
}

# ---------------------------------------------------------------------------
# proc: _SANITIZE_IP_KEY
#
# Replace characters in an IP address that could be problematic in a table
# key. Specifically replaces colons in IPv6 addresses with underscores.
# ---------------------------------------------------------------------------
proc _SANITIZE_IP_KEY { ip } {
    return [string map {: _} $ip]
}

# ---------------------------------------------------------------------------
# proc: _PARSE_JWT_EXP
#
# Extract the expiry (exp) claim from a JWT token.
# JWT payload is base64url encoded. TCL base64 does not handle base64url so
# we translate the alphabet before decoding. Padding is added as needed since
# JWT omits it. The exp field is extracted with a regex.
#
# The pattern uses double-quote delimited strings to avoid TCL interpreting
# the JSON quotes as brace delimiters.
#
# Returns 0 on any parse failure so the caller treats the token as expired.
# ---------------------------------------------------------------------------
proc _PARSE_JWT_EXP { token } {
    # Split on dots and take the payload (second segment).
    set PARTS [split $token "."]

    if { [llength $PARTS] != 3 } {
        return 0
    }

    set PAYLOAD_B64URL [lindex $PARTS 1]

    # Translate base64url alphabet to standard base64.
    set PAYLOAD_B64 [string map {- + _ /} $PAYLOAD_B64URL]

    # Add missing base64 padding - JWT omits trailing = characters.
    set PAD [expr { (4 - ([string length $PAYLOAD_B64] % 4)) % 4 }]
    append PAYLOAD_B64 [string repeat "=" $PAD]

    # Decode - wrap in catch because malformed input will throw.
    if { [catch { set DECODED [b64decode $PAYLOAD_B64] } ERR] } {
        return 0
    }

    # Extract the exp integer from the decoded JSON payload.
    # Pattern: "exp" followed by optional whitespace, colon, whitespace,
    # then one or more digits captured in group 1.
    if { [regexp {"exp"\s*:\s*(\d+)} $DECODED -> EXP_VAL] } {
        return $EXP_VAL
    }

    return 0
}

# ---------------------------------------------------------------------------
# proc: _GET_EPOCH
#
# Return current Unix epoch as integer.
# ---------------------------------------------------------------------------
proc _GET_EPOCH {} {
    return [clock seconds]
}

# ---------------------------------------------------------------------------
# proc: _BUILD_HSSR_ARGS
#
# Build a base HSSR argument list in the caller's context via upvar.
# If the named variable already exists it is appended to, not cleared.
# Adds -method, -uri, -timeout, -virt and optionally -ns (when the dns
# setting is non-empty).
#
# Arguments:
#   var_name  - Name of the list variable in the caller's scope
#   method    - HTTP method (GET or POST)
#   uri       - Full URL including path and query string
# ---------------------------------------------------------------------------
proc _BUILD_HSSR_ARGS { var_name method uri } {
    upvar 1 $var_name ARGS

    set TIMEOUT $static::MIDEYE_SHIELD_api_timeout
    set HELPER  $static::MIDEYE_SHIELD_hssr_helper_vs
    set DNS     $static::MIDEYE_SHIELD_dns

    lappend ARGS \
        -method  $method \
        -uri     $uri \
        -timeout $TIMEOUT \
        -virt    $HELPER

    if { $DNS != "" } {
        lappend ARGS -ns $DNS
    }
}

# ---------------------------------------------------------------------------
# proc: _MARK_API_DOWN
#
# Record that the API is currently unreachable and set the cache TTL based
# on the api_down_cache_time setting.
# ---------------------------------------------------------------------------
proc _MARK_API_DOWN {} {
    set DOWN_TIME $static::MIDEYE_SHIELD_api_down_cache_time
    call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_SET "api_down" 1 $DOWN_TIME $DOWN_TIME
}

# ---------------------------------------------------------------------------
# proc: _IS_API_DOWN
#
# Returns 1 if the API is currently marked as down in the cache, 0 otherwise.
# ---------------------------------------------------------------------------
proc _IS_API_DOWN {} {
    set STATE [call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_GET "api_down"]

    if { $STATE eq "1" } {
        return 1
    }

    return 0
}

# ---------------------------------------------------------------------------
# proc: _GET_VALID_TOKEN
#
# Return a valid API access token, fetching a new one if needed.
#
# Uses a binary "token_fetching" lock to prevent concurrent refresh storms.
# The lock is claimed with "table add", which writes only if the key is absent,
# and ownership is decided from what that call returns. Note the limitation:
# the sentinel written is 1, so under the reading where a declined add returns
# the existing value, owning and not owning are indistinguishable and every
# racing context fetches. The lock then damps nothing, though each caller still
# ends up with a valid token. A caller that does not win polls until the new
# token appears or the timeout is exhausted.
#
# Returns empty string on failure.
# ---------------------------------------------------------------------------
proc _GET_VALID_TOKEN {} {
    set SAFEGUARD     $static::MIDEYE_SHIELD_api_token_safeguard
    set TIMEOUT       $static::MIDEYE_SHIELD_api_timeout
    set TOKEN_URL     $static::MIDEYE_SHIELD_api_token_url
    set CLIENT_ID     $static::MIDEYE_SHIELD_api_client_id
    set CLIENT_SECRET $static::MIDEYE_SHIELD_api_client_secret
    set SCOPE         $static::MIDEYE_SHIELD_api_scope
    set POLL_INTERVAL $static::MIDEYE_SHIELD_pending_poll_interval
    set NOW           [call /__partition__/MIDEYE_SHIELD_COMMON::_GET_EPOCH]

    # Return cached token if it still has enough lifetime remaining.
    set CACHED_TOKEN [call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_GET "token"]

    if {$CACHED_TOKEN != ""} {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "Returning cached token..."
        return $CACHED_TOKEN
    }

    # Attempt to claim the fetch lock atomically.
    # "table add" only inserts if the key is absent.
    # Returns empty string when we own the lock, existing value otherwise.
    set SENTINEL_TTL [expr { int($TIMEOUT / 1000) + 5 }]
    set LOCK_RESULT  [table add -subtable "MIDEYE_SHIELD" "token_fetching" 1 $SENTINEL_TTL indefinite]

    call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "LOCK_RESULT: $LOCK_RESULT"

    if { $LOCK_RESULT != 1 } {
        # Another context holds the lock - poll until token appears.
        set MAX_POLLS [expr { int($TIMEOUT / $POLL_INTERVAL) + 1}]
        set POLLS 0

        while {$POLLS < $MAX_POLLS} {
            # Wait for lock to release
            after $POLL_INTERVAL

            set CACHED_TOKEN [call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_GET "token"]

            if {$CACHED_TOKEN != ""} {
                return $CACHED_TOKEN
            }

            incr POLLS
        }

        # Timed out waiting for the owning context to complete the fetch.
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "TIMEOUT WAITING for other thread fetching a TOKEN"
        return ""
    }

    # We own the lock (LOCK_RESULT was 1). Perform the token fetch.
    set BODY "grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&scope=${SCOPE}"

    # Build the HSSR argument list with common options and optional DNS.
    call /__partition__/MIDEYE_SHIELD_COMMON::_BUILD_HSSR_ARGS ARGS "POST" "${TOKEN_URL}"

    lappend ARGS \
        -body   $BODY \
        -type   "application/x-www-form-urlencoded" \
        -rbody  RESP_BODY

    # Perform the sideband token request via HSSR.
    # http_req returns the HTTP status code directly.
    # The response body is received into RESP_BODY via -rbody.
    if { [catch {
        set STATUS [call __hssr_irule__::http_req $ARGS]
    } ERR] } {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "Unable to get valid token -> '$ERR'"

        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL "token_fetching"
        return ""
    }

    if { $STATUS != 200 } {
        if {not([info exists RESP_BODY])} {
            set RESP_BODY ""
        }

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "Unable to get valid token, status $STATUS -> '$RESP_BODY'"

        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL "token_fetching"
        return ""
    }

    # Extract the access_token value from the JSON response body.
    # The pattern matches: "access_token" : "< captured value >"
    if { ![regexp {"access_token"\s*:\s*"([^"]+)"} $RESP_BODY -> NEW_TOKEN] } {    #" <-- syntax highlighting WO
        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL "token_fetching"

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "Unable to extract token value from JSON -> '$RESP_BODY'"
        return ""
    }

    call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "GOT A NEW_TOKEN" true

    # Parse the exp claim from the token so we honour the server-issued lifetime.
    set EXP [call /__partition__/MIDEYE_SHIELD_COMMON::_PARSE_JWT_EXP $NEW_TOKEN]

    call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "TOKEN EXP: '$EXP'"

    if { $EXP == 0 } {
        # Could not parse exp - fall back to a conservative 5-minute cache.
        set EXP [expr { [call /__partition__/MIDEYE_SHIELD_COMMON::_GET_EPOCH] + 300 }]
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "Setting default EXP to: '$EXP'"
    }

    # Cache the token and its expiry using the remaining token lifetime as TTL.
    set TTL [expr {$EXP - [call /__partition__/MIDEYE_SHIELD_COMMON::_GET_EPOCH] - $SAFEGUARD}]

    call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "TOKEN TTL: '$TTL'"

    # Save the new token in the cahce
    call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_SET "token" $NEW_TOKEN $TTL $TTL

    # Release the lock so a future expiry triggers a fresh fetch.
    call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL "token_fetching"

    return $NEW_TOKEN
}

# ---------------------------------------------------------------------------
# proc: _FETCH_IP_SCORE
#
# Call the Shield API to get a risk score for the given IP address.
# Manages the pending-connections counter and the score sentinel (-1).
#
# The API returns a JSON object with a nested riskScore structure:
#   {"ipAddress":"x.x.x.x","riskScore":{"overall":N,"severity":N,"velocity":N}}
# The "overall" field is used as the score for allow/deny decisions.
#
# The cache_time argument controls how long the resolved score is cached.
# Callers pass different values depending on context (connection vs login).
#
# The pending counter uses "table incr" for the initial claim (first caller
# gets 1 and becomes the API fetcher) and "table incr <key> -1" to release
# the slot when a waiter is done. Both operations are atomic.
#
# Return values:
#   0-100  - resolved score from the API
#   -2     - API failure (token unavailable, request error, bad response)
#   -3     - pending queue for this IP is full (deny_pending_max)
# ---------------------------------------------------------------------------
proc _FETCH_IP_SCORE { client_ip cache_time } {
    set TCP_COLLECT     {TCP::collect}
    set TCP_RELEASE     {TCP::release}
    set SAFE_IP         [call /__partition__/MIDEYE_SHIELD_COMMON::_SANITIZE_IP_KEY $client_ip]
    set SCORE_KEY       "score_${SAFE_IP}"
    set PEND_KEY        "pending_${SAFE_IP}"
    set TIMEOUT         $static::MIDEYE_SHIELD_api_timeout
    set PENDING_MAX     $static::MIDEYE_SHIELD_pending_max
    set POLL_INTERVAL   $static::MIDEYE_SHIELD_pending_poll_interval
    set BASE_URL        $static::MIDEYE_SHIELD_api_base_url

    set SCORE_PATH    /ips

    # --- Cache check ---
    set CACHED    [call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_GET $SCORE_KEY]

    # Check if we have a cached value
    if {$CACHED != "" && $CACHED >= 0} {
        set CACHED_VALUE_LIFETIME [table lookup -subtable "MIDEYE_SHIELD" $SCORE_KEY]

        if {$CACHED_VALUE_LIFETIME != -1 && $CACHED_VALUE_LIFETIME <= $cache_time} {
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_cache_hits"
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_INFO "Using Cached Risk Score of '$CACHED' for '$client_ip'"

            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
            return $CACHED
        } else {
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_INFO "Cached Risk Score for '$client_ip' has been cached for too long for this validation, deleting..."
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $SCORE_KEY
        }
    }

    call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_cache_misses"

    # If the API is known to be down, fail open immediately.
    if {[call /__partition__/MIDEYE_SHIELD_COMMON::_IS_API_DOWN]} {
        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_api_fail"
        #call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_allowed_apifail"
        return -2
    }

    # Missing cached value, we need to fetch a score from the API
    #
    # Atomically increment the pending counter for this IP.
    # The first caller gets 1 and is elected as the API caller.
    # All subsequent callers get a higher value and become waiters.
    set PEND_VAL [table incr -subtable "MIDEYE_SHIELD" $PEND_KEY]

    # Check if this is the first thread that need a score for this IP
    if {$PEND_VAL == 1} {
        # We are the first caller, set TTLs and write the investigation sentinel.
        # The pending key TTL is tied to api_timeout so it self-clears on crash.
        set TIMEOUT_SECS [expr { int($TIMEOUT / 1000) + 1 }]

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "Will fetch Score for '$SAFE_IP', PEND_VAL: $PEND_VAL"

        set TOKEN [call /__partition__/MIDEYE_SHIELD_COMMON::_GET_VALID_TOKEN]

        if {$TOKEN == ""} {
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $SCORE_KEY
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
            call /__partition__/MIDEYE_SHIELD_COMMON::_MARK_API_DOWN

            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "WARNING: Unable to fetch API Token"
            return -2
        }

        # Build the HSSR argument list with common options and optional DNS.
        call /__partition__/MIDEYE_SHIELD_COMMON::_BUILD_HSSR_ARGS ARGS "GET" "${BASE_URL}${SCORE_PATH}/${client_ip}"
        lappend ARGS \
            -headers [list "Authorization" "Bearer ${TOKEN}"] \
            -rbody   RESP_BODY

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "Fetching Score for '$SAFE_IP'"

        # Perform the sideband score request via HSSR.
        # http_req returns the HTTP status code directly.
        # The response body is received into RESP_BODY via -rbody.
        if { [catch {
            set STATUS [call __hssr_irule__::http_req $ARGS]
        } ERR] } {
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $SCORE_KEY
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
            call /__partition__/MIDEYE_SHIELD_COMMON::_MARK_API_DOWN

            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "WARNING: Unable to fetch IP Score from API"
            return -2
        }

        if { $STATUS != 200 } {
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $SCORE_KEY
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
            call /__partition__/MIDEYE_SHIELD_COMMON::_MARK_API_DOWN

            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "WARNING: Unable to fetch IP Score from API ($STATUS) -> '{$RESP_BODY}'"
            return -2
        }

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "Fetch TOKEN RESP_BODY: $RESP_BODY"

        # Parse the overall risk score from the JSON response body.
        # The API returns: {"ipAddress":"...","riskScore":{"overall":N,...}}
        # Pattern matches: "overall" : <digits> inside the riskScore object.
        if { ![regexp {"overall"\s*:\s*(\d+)} $RESP_BODY -> SCORE] } {
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $SCORE_KEY
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
            call /__partition__/MIDEYE_SHIELD_COMMON::_MARK_API_DOWN

            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "WARNING: Unable to parse riskScore.overall from API Response -> '{$RESP_BODY}'"
            return -2
        }

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "SCORE: SCORE: '$SCORE' for '$SAFE_IP'"

        # Decide the cache TTL for this resolved score. A score that will be
        # hard-denied does not need to be re-checked against the API every few
        # seconds, so it is cached for much longer (deny_cache_time, default
        # 24h). Any score below the hard-deny threshold keeps the caller's
        # normal TTL (the connection or login cache time).
        set HARD_DENY_THRESHOLD $static::MIDEYE_SHIELD_score_hard_deny
        set DENY_CACHE_TIME     $static::MIDEYE_SHIELD_score_deny_cache_time

        set EFFECTIVE_CACHE_TIME $cache_time

        if { $SCORE >= $HARD_DENY_THRESHOLD } {
            set EFFECTIVE_CACHE_TIME $DENY_CACHE_TIME
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "Caching denied IP '$SAFE_IP' score '$SCORE' for extended TTL '$EFFECTIVE_CACHE_TIME's"
        }

        # Write the resolved score to cache and release the pending key.
        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_SET $SCORE_KEY $SCORE $EFFECTIVE_CACHE_TIME $EFFECTIVE_CACHE_TIME
        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY

        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_api_success"
        return $SCORE

    # Else someone else is fetching the Score and we just need to wait for that thread
    } else {
        # We are a waiter. Reject immediately if the queue is already full.
        if {$PEND_VAL > $PENDING_MAX} {
            # Release our slot with an atomic decrement before returning.
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "WARNING: Requests in queue, rejecting due to full wait list"

            set NEW_PENDING_COUNT [table incr -subtable "MIDEYE_SHIELD" $PEND_KEY -1]

            # TODO check the value 2000
            if {$NEW_PENDING_COUNT > 2000 || $NEW_PENDING_COUNT <= 0} {
                call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
            }

            return -3
        }

        # Poll the score key until it resolves, is deleted, or we time out.
        set MAX_POLLS [expr { int($TIMEOUT / $POLL_INTERVAL) }]
        set POLLS 0

        set MIDEYE_SHIELD_WAITING 1
        catch {
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "Will try to COLLECT Data (POLLS: $MAX_POLLS, TIME: $POLL_INTERVAL)"
            eval $TCP_COLLECT
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "COLLECT Succeded"
        }

        while {$POLLS < $MAX_POLLS} {
            after $POLL_INTERVAL

            set CACHED_SCORE [call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_GET $SCORE_KEY]

            # A real score (not the -1 sentinel) means the fetcher succeeded.
            if { $CACHED_SCORE != "" && $CACHED_SCORE != -1 } {
                call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
                catch { eval $TCP_RELEASE }
                set MIDEYE_SHIELD_WAITING 0
                return $CACHED_SCORE
            }

            # Empty key means the fetcher deleted it due to an API failure.
            if { $CACHED_SCORE == "" } {
                call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
                call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "WARNING: API Failure?"
                catch { eval $TCP_RELEASE }
                set MIDEYE_SHIELD_WAITING 0
                return -2
            }

            incr POLLS
        }

        catch { eval $TCP_RELEASE }
        set MIDEYE_SHIELD_WAITING 0

        # Timed out waiting for the fetcher - treat as API failure.
        set NEW_PENDING_COUNT [table incr -subtable "MIDEYE_SHIELD" $PEND_KEY -1]

        # TODO check the value 2000
        if {$NEW_PENDING_COUNT > 2000 || $NEW_PENDING_COUNT <= 0} {
            call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
        }

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "WARNING: Timeout waiting for API Caller"
        return -2
    }
}

# ---------------------------------------------------------------------------
# proc: _REPORT_BLOCK
#
# Buffer one "blocked" event for an IP the BIG-IP refused. Fire-and-forget.
#
# Only ever called after a branch's dry-run check, so an event can only follow a
# block that actually happened. The pending-queue-full deny deliberately does
# not call this: that is a capacity deny of a possibly-innocent IP.
#
# enforced_name distinguishes why we refused (score_hard_deny / blacklist).
# ---------------------------------------------------------------------------
proc _REPORT_BLOCK { client_ip enforced_name } {
    # Compared against "0" rather than "1" so an iRule installed by hand, with
    # the placeholder unsubstituted, still reports.
    if { $static::MIDEYE_SHIELD_block_enabled == "0" } { return }

    # Reporting a block must never change what happens to the connection: an
    # uncaught throw here would abort the caller's iRule event, mid-policy on
    # the APM path.
    if { [catch {
        set VS ""
        catch { set VS [virtual name] }

        # enforcedBy.id is required and min_length 1 in the API schema; an empty
        # id would fail validation for the whole batch, not just this event.
        if { $VS eq "" } { set VS "mideye_shield" }

        set TS [clock format [clock seconds] -format {%Y-%m-%dT%H:%M:%S%z}]

        set J "\{\"ipAddress\":\"[call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE $client_ip]\""
        append J ",\"observedAt\":\"$TS\""
        append J ",\"authentication\":\{\"outcome\":\"blocked\""
        append J ",\"enforcedBy\":\{\"id\":\"[call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE $VS]\""
        append J ",\"name\":\"[call /__partition__/MIDEYE_SHIELD_COMMON::_JSON_ESCAPE $enforced_name]\""
        append J ",\"type\":\"irule\",\"provider\":\"f5_bigip\"\}\}\}"

        call /__partition__/MIDEYE_SHIELD_COMMON::_ENQUEUE_EVENT "MIDEYE_SHIELD_BLOCKS" $J \
            $static::MIDEYE_SHIELD_block_batch_size \
            $static::MIDEYE_SHIELD_block_flush_interval \
            $static::MIDEYE_SHIELD_block_max_buffer
    } err] } {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "Something went wrong reporting a block for '$client_ip': '$err'"
    }
}

# ---------------------------------------------------------------------------
# proc: _VALIDATE
#
# Internal shared validation logic used by VALIDATE_CONNECTION and
# VALIDATE_LOGIN. The cache_time argument determines how long a resolved
# score is cached, allowing different TTLs per call context.
#
# Returns 1 to allow, 0 to reject.
# ---------------------------------------------------------------------------
proc _VALIDATE { client_ip cache_time } {
    # Read control flags and thresholds once to stay consistent for this call.
    set DISABLED            $static::MIDEYE_SHIELD_disabled
    set DRY_RUN             $static::MIDEYE_SHIELD_dry_run
    set HARD_DENY_THRESHOLD $static::MIDEYE_SHIELD_score_hard_deny
    set WARN_THRESHOLD      $static::MIDEYE_SHIELD_score_warn

    call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "INSIDE _VALIDATE $client_ip $cache_time: DISABLED: $DISABLED"

    call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_requests"

    # Disabled flag short-circuits everything - no logging, no checks.
    if {$DISABLED == "1"} {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "INSIDE _VALIDATE exit branch 1 (Disabled)"
        return 1
    }

    # Clean up the IP from potential Route Domain
    set client_ip [lindex [split $client_ip "%"] 0]

    # --- Blacklist check (highest priority) ---
    if {[class match $client_ip equals /__base_partition__/MIDEYE_SHIELD_BLACKLIST]} {
        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_blacklisted"

        # Above the dry-run check, as on the score branch.
        if {$DRY_RUN == "1"} {
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "DRY RUN - Would have denied '$client_ip' due to blacklist match"
            return 1
        }

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_INFO "IP '$client_ip' DENIED due to blacklist match"
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "INSIDE _VALIDATE exit branch 2 (Blacklisted)"
        call /__partition__/MIDEYE_SHIELD_COMMON::_REPORT_BLOCK $client_ip "blacklist"
        return 0
    }

    # --- Whitelist check ---
    if {[class match $client_ip equals /__base_partition__/MIDEYE_SHIELD_WHITELIST]} {
        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_whitelisted"
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "INSIDE _VALIDATE exit branch 3 (Whitelisted)"
        return 1
    }

    # --- Get New or Cached Risk Score ---
    # Fetch the score, handles pending counter and wait logic internally.
    # Pass cache_time so the fetcher caches with the correct TTL.
    set SCORE [call /__partition__/MIDEYE_SHIELD_COMMON::_FETCH_IP_SCORE $client_ip $cache_time]

    # Pending queue for this IP is full - treat as a hard deny.
    if {$SCORE == -3} {
        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_blocked"

        if {$DRY_RUN == "1"} {
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "DRY RUN - Would have denied IP due to too many pending connections from '$client_ip'"
            return 1
        }

        # TODO, config for this?
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "INSIDE _VALIDATE exit branch 5 (Pending Queue FULL)"
        return 0
    }

    # API failure or timeout waiting for a score - fail open.
    if {$SCORE == -2} {
        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_allowed_apifail"
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "INSIDE _VALIDATE exit branch 6 (API Timeout)"
        return 1
    }

    # --- Score evaluation ---
    if {$SCORE >= $HARD_DENY_THRESHOLD} {
        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_blocked"

        if {$DRY_RUN == "1"} {
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "DRY RUN - Would have denied '$client_ip' due to high score of '$SCORE'"
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "INSIDE _VALIDATE exit branch 7 (Dry Run, and HIGH Score)"
            return 1
        }

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_INFO "DENY '$client_ip' due to too high score '$SCORE'"
        call /__partition__/MIDEYE_SHIELD_COMMON::_REPORT_BLOCK $client_ip "score_hard_deny"
        return 0
    }

    if {$SCORE >= $WARN_THRESHOLD} {
        call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_allowed_score"
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "WARNING '$client_ip' score '$SCORE' is inside the warn band"
        return 1
    }

    call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_allowed_score"
    call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "INSIDE _VALIDATE main exit (ALLOWED)"
    return 1
}

# ===========================================================================
# P U B L I C   P R O C E D U R E S
# ===========================================================================

# ---------------------------------------------------------------------------
# proc: LOG_ALERT
#
# Sends log message to the ALERT log
#
# Returns void
# ---------------------------------------------------------------------------
proc LOG_ALERT {msg {noname false}} {
    call /__partition__/MIDEYE_SHIELD_COMMON::_LOG_COMMON alert $msg $noname
}

# ---------------------------------------------------------------------------
# proc: LOG_ERROR
#
# Sends log message to the ERROR log
#
# Returns void
# ---------------------------------------------------------------------------
proc LOG_ERROR {msg {noname false}} {
    call /__partition__/MIDEYE_SHIELD_COMMON::_LOG_COMMON error $msg $noname
}

# ---------------------------------------------------------------------------
# proc: LOG_WARNING
#
# Sends log message to the WARN log
#
# Returns void
# ---------------------------------------------------------------------------
proc LOG_WARNING {msg {noname false}} {
    call /__partition__/MIDEYE_SHIELD_COMMON::_LOG_COMMON warning $msg $noname
}

# ---------------------------------------------------------------------------
# proc: LOG_INFO
#
# Sends log message to the INFO log
#
# Returns void
# ---------------------------------------------------------------------------
proc LOG_INFO {msg {noname false}} {
    call /__partition__/MIDEYE_SHIELD_COMMON::_LOG_COMMON info $msg $noname
}

# ---------------------------------------------------------------------------
# proc: LOG_DEBUG
#
# Sends log message to the DEBUG log if debug has been enabled in settings
#
# Returns void
# ---------------------------------------------------------------------------
proc LOG_DEBUG {msg {noname false}} {
    if {$static::MIDEYE_SHIELD_log_debug == 1} {
        call /__partition__/MIDEYE_SHIELD_COMMON::_LOG_COMMON debug $msg $noname
    }
}

# ---------------------------------------------------------------------------
# proc: VALIDATE_CONNECTION
#
# Validates an IP at the TCP connection level. Uses score_cache_time from
# settings as the cache TTL, which is typically a longer value (e.g. 300s).
#
# Returns 1 to allow, 0 to reject.
#
#   if { ![call /__partition__/MIDEYE_SHIELD_COMMON::VALIDATE_CONNECTION [IP::client_addr]] } {
#       reject
#   }
# ---------------------------------------------------------------------------
proc VALIDATE_CONNECTION { client_ip } {
    set CACHE_TIME $static::MIDEYE_SHIELD_score_cache_time
    return [call /__partition__/MIDEYE_SHIELD_COMMON::_VALIDATE $client_ip $CACHE_TIME]
}

# ---------------------------------------------------------------------------
# proc: VALIDATE_LOGIN
#
# Validates an IP at the login/APM level. Uses login_score_cache_time from
# settings as the cache TTL, which is typically a shorter value (e.g. 10s)
# to ensure a fresher score is used before authenticating a user.
#
# Returns 1 to allow, 0 to reject.
#
#   if { ![call /__partition__/MIDEYE_SHIELD_COMMON::VALIDATE_LOGIN [IP::client_addr]] } {
#       reject
#   }
# ---------------------------------------------------------------------------
proc VALIDATE_LOGIN { client_ip } {
    set CACHE_TIME $static::MIDEYE_SHIELD_login_score_cache_time
    return [call /__partition__/MIDEYE_SHIELD_COMMON::_VALIDATE $client_ip $CACHE_TIME]
}

# ---------------------------------------------------------------------------
# proc: REPORT_AUTH_RESULT
#
# Report an authentication result for an IP back to the Shield API.
#
# Called from the APM iRule after ACCESS_POLICY_COMPLETED.
# This is fire-and-forget - errors are logged but never propagated.
# ---------------------------------------------------------------------------
proc REPORT_AUTH_RESULT { client_ip { reported_by "" } } {
    set status ""

    catch {
        set TOKEN [call /__partition__/MIDEYE_SHIELD_COMMON::_GET_VALID_TOKEN]

        if {$TOKEN == ""} {
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "REPORT_AUTH_RESULT - No valid API token, skipping report for '$client_ip'"
            return
        }

        set SALT        $static::MIDEYE_SHIELD_username_salt

        set BASE_URL    $static::MIDEYE_SHIELD_api_base_url
        set REPORT_PATH /ips/events

        set reason  [string tolower [ACCESS::session data get session.custom.shield.reason]]
        set method  [string tolower [ACCESS::session data get session.custom.shield.method]]
        set user    [ACCESS::session data get session.logon.last.username]
        set outcome $reason

        if {$SALT == ""} {
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "username_salt is empty, consider setting a unique value in the Mideye Shield iApp"
        }

        if {$method == ""} {
            set method "unknown"
        }

        if {$reason == ""} {
            # If the reason was not set, we just skip reporting
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_INFO "Reason was not set, will skip reporting, ipAddress: '$client_ip', username: '$user'"
            return
        }

        set hashed_user ""
        if {$user != ""} {
            call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "Will HASH: '${SALT}${user}'"
            binary scan [sha512 "${SALT}${user}"] H* hashed_user
        }

        set BODY    "\{"
        append BODY "\"events\": \["
        append BODY "\{"
        append BODY "\"ipAddress\":\"${client_ip}\""
        append BODY ",\"observedAt\": \"[clock format [clock seconds] -format {%Y-%m-%dT%H:%M:%S%z}]\""
        append BODY ",\"authentication\": \{"
        append BODY "\"outcome\": \"$outcome\""

        if {$reported_by != ""} {
            append BODY ",\"enforcedBy\": {\"id\": \"$reported_by\"}"
        }

        if {$hashed_user != ""} {
            append BODY ",\"usernameHash\": \"$hashed_user\""
        }

        if {$outcome == "success"} {
            append BODY ",\"method\": \"$method\""
        }

        append BODY "\}"
        append BODY "\}"
        append BODY "\]"
        append BODY "\}"

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "Sending Auth Result: Outcome: '$outcome', ipAddress: '$client_ip', reported_by: '$reported_by', username: '$user'"

        # Build the HSSR argument list with common options and optional DNS.
        call /__partition__/MIDEYE_SHIELD_COMMON::_BUILD_HSSR_ARGS ARGS "POST" "${BASE_URL}${REPORT_PATH}"
        lappend ARGS \
            -headers [list "Authorization" "Bearer ${TOKEN}"] \
            -body    $BODY \
            -type    "application/json"

        # Fire and forget - catch but discard any error.
        catch {
            set status [call __hssr_irule__::http_req $ARGS]
        }
    } err

    if {$err != "" && $err != 0} {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_WARNING "Something went wrong when sending result to SHIELD: '$err'"
    } else {
        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "STATUS CODE from /ips/events: '$status'"
    }
}

# ---------------------------------------------------------------------------
# proc: GET_STATS
#
# Return a flat {key value key value ...} list of all statistics counters.
# Callers iterate it with:
#   foreach {K V} [call /__partition__/MIDEYE_SHIELD_COMMON::GET_STATS] { ... }
#
# Note: the snapshot is not atomic across all keys - use for monitoring only.
# ---------------------------------------------------------------------------
proc GET_STATS {} {
    set KEYS {
        stat_requests
        stat_blacklisted
        stat_whitelisted
        stat_cache_hits
        stat_cache_misses
        stat_api_success
        stat_api_fail
        stat_allowed_apifail
        stat_allowed_score
        stat_blocked
    }

    set RESULT {}

    foreach KEY $KEYS {
        set VAL [call /__partition__/MIDEYE_SHIELD_COMMON::_TBL_GET $KEY]

        if { $VAL eq "" } {
            set VAL 0
        }

        lappend RESULT $KEY $VAL
    }

    return $RESULT
}

# ---------------------------------------------------------------------------
# proc: RESET_STATS
#
# Reset all statistics counters to zero.
# ---------------------------------------------------------------------------
proc RESET_STATS {} {
    set KEYS {
        stat_requests
        stat_blacklisted
        stat_whitelisted
        stat_cache_hits
        stat_cache_misses
        stat_api_success
        stat_api_fail
        stat_allowed_apifail
        stat_allowed_score
        stat_blocked
    }

    foreach KEY $KEYS {
        table set -subtable "MIDEYE_SHIELD" $KEY 0 indefinite indefinite
    }
}

# These two events are needed so we can use "after" while waiting
# for another task to complete fetching of a score to the local cache
when CLIENT_ACCEPTED {
    set MIDEYE_SHIELD_WAITING 0
}

when CLIENT_DATA {
    # If we are waiting, we need to keep collecting data until it has finished
    if {$MIDEYE_SHIELD_WAITING == 1} {
        TCP::collect
        return
    }
}
