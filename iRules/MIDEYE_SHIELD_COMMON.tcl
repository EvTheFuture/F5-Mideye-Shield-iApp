# =============================================================================
# iRule   : MIDEYE_SHIELD_COMMON
# Version : 0.9.3
# Author  : Magnus Sandin, Valitron AB
# Date    : 2026-03-20
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
# Description
# -----------
# Procs are called from other iRules using the full iRule path syntax:
#   call /Common/MIDEYE_SHIELD_COMMON::<PROCNAME> <args>
#
# The session subtable name is hardcoded as the constant string "MIDEYE_SHIELD"
# in every proc rather than held in a variable.
#
# The token_fetching sentinel uses "table add" (-excl semantics) rather than
# incr, because it is a binary lock - not a counter. "table add" only writes
# if the key does not already exist, and returns the existing value if it does.
# This gives a single atomic test-and-set with no read-modify-write gap.
#
#
# Procedures exposed
# ------------------
#   /Common/MIDEYE_SHIELD_COMMON::VALIDATE_CONNECTION  client_ip
#       Validates an IP at the TCP connection level using score_cache_time.
#       Returns 1 to allow, 0 to reject.
#       All logging and counter updates are handled internally.
#       In dry_run mode always returns 1 but logs what would have been denied.
#
#   /Common/MIDEYE_SHIELD_COMMON::VALIDATE_LOGIN  client_ip
#       Validates an IP at the login/APM level using login_score_cache_time.
#       Returns 1 to allow, 0 to reject.
#       Otherwise identical behaviour to VALIDATE_CONNECTION.
#       Use this when a shorter cache time is appropriate, e.g. before
#       authenticating a user where a fresher score is desirable.
#
#   /Common/MIDEYE_SHIELD_COMMON::REPORT_AUTH_RESULT  client_ip  auth_result
#       Fire-and-forget report of an auth outcome back to the Shield API.
#       Called from the APM iRule after ACCESS_POLICY_COMPLETED.
#       auth_result must be either "allow" or "deny".
#
#   /Common/MIDEYE_SHIELD_COMMON::GET_STATS
#       Returns a flat {key value key value ...} list of all counters.
#       Iterate with: foreach {K V} [call /Common/MIDEYE_SHIELD_COMMON::GET_STATS] {}
#
#   /Common/MIDEYE_SHIELD_COMMON::RESET_STATS
#       Resets all statistics counters to zero.
#
#
# Dependencies - Data Groups
# --------------------------
# All data groups must exist on the BIG-IP before this iRule is used.
#
#   MIDEYE_SHIELD_SETTINGS  (string type)
#       Key/value pairs controlling Shield behaviour. Required keys:
#
#       api_client_id           - OAuth2 client ID for Shield API
#       api_client_secret       - OAuth2 client secret for Shield API
#       api_base_url            - Base URL, e.g. https://shield.example.com
#       api_timeout             - Sideband call timeout in ms, e.g. 3000
#       api_token_safeguard     - Seconds to shave off token lifetime, e.g. 30
#       api_down_cache_time     - Seconds to cache API-down state, e.g. 60
#       api_retry_after         - Seconds before retrying API after down, e.g. 30
#       score_cache_time        - Seconds to cache a resolved IP score for connections, e.g. 300
#       login_score_cache_time  - Seconds to cache a resolved IP score for logins, e.g. 10
#       score_hard_deny         - Score at or above this value is denied, e.g. 75
#       score_warn              - Score at or above this value gets a warning, e.g. 50
#       pending_max             - Max connections waiting for one IP, e.g. 10
#       pending_poll_interval   - Poll interval in ms while waiting, e.g. 100
#       disabled                - Set to 1 to bypass all checks
#       dry_run                 - Set to 1 to evaluate but never hard-reject
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
#           call /Common/HSSR::request <options list>
#       and expects a two-element list response: {status body}
#           lindex $RESPONSE 0  - HTTP status code as integer
#           lindex $RESPONSE 1  - HTTP response body as string
#
#
# Dependencies - Session Table (subtable)
# ----------------------------------------
# All table keys live in the subtable "MIDEYE_SHIELD" to avoid collisions.
# Key naming conventions used internally:
#
#   score_<ip>            - Cached score for an IP (-1 = under investigation)
#   pending_<ip>          - Number of connections waiting for this IP's score
#   token                 - Cached API access token string
#   token_exp             - Token expiry as Unix epoch integer
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
# =============================================================================

# ===========================================================================
# P R I V A T E   P R O C E D U R E S
# ===========================================================================

# ---------------------------------------------------------------------------
# proc: _DG_GET
#
# Read a single key from the settings data group.
#
# Returns empty string if the key does not exist.
# ---------------------------------------------------------------------------
proc _DG_GET { key } {
    return [class match -value $key equals MIDEYE_SHIELD_SETTINGS]
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
# proc: _MARK_API_DOWN
#
# Record that the API is currently unreachable and set the cache TTL based
# on the api_down_cache_time setting.
# ---------------------------------------------------------------------------
proc _MARK_API_DOWN {} {
    set DOWN_TIME [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_down_cache_time"]
    call /Common/MIDEYE_SHIELD_COMMON::_TBL_SET "api_down" 1 $DOWN_TIME $DOWN_TIME
}

# ---------------------------------------------------------------------------
# proc: _IS_API_DOWN
#
# Returns 1 if the API is currently marked as down in the cache, 0 otherwise.
# ---------------------------------------------------------------------------
proc _IS_API_DOWN {} {
    set STATE [call /Common/MIDEYE_SHIELD_COMMON::_TBL_GET "api_down"]

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
# The lock is claimed with "table add" which is an atomic test-and-set:
# it only writes if the key is absent and returns the existing value if not.
# A caller that finds the key already present knows another context owns the
# fetch and polls until the new token appears or the timeout is exhausted.
#
# Returns empty string on failure.
# ---------------------------------------------------------------------------
proc _GET_VALID_TOKEN {} {
    set SAFEGUARD     [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_token_safeguard"]
    set TIMEOUT       [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_timeout"]
    set BASE_URL      [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_base_url"]
    set TOKEN_PATH    [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_token_path"]
    set CLIENT_ID     [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_client_id"]
    set CLIENT_SECRET [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_client_secret"]
    set POLL_INTERVAL [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "pending_poll_interval"]
    set NOW           [call /Common/MIDEYE_SHIELD_COMMON::_GET_EPOCH]

    # Return cached token if it still has enough lifetime remaining.
    set CACHED_TOKEN [call /Common/MIDEYE_SHIELD_COMMON::_TBL_GET "token"]
    set TOKEN_EXP    [call /Common/MIDEYE_SHIELD_COMMON::_TBL_GET "token_exp"]

    if { $CACHED_TOKEN ne "" && $TOKEN_EXP ne "" } {
        if { ($TOKEN_EXP - $SAFEGUARD) > $NOW } {
            return $CACHED_TOKEN
        }
    }

    # Attempt to claim the fetch lock atomically.
    # "table add" only inserts if the key is absent.
    # Returns empty string when we own the lock, existing value otherwise.
    set SENTINEL_TTL [expr { int($TIMEOUT / 1000) + 5 }]
    set LOCK_RESULT  [table add -subtable "MIDEYE_SHIELD" "token_fetching" 1 $SENTINEL_TTL indefinite]

    if { $LOCK_RESULT ne "" } {
        # Another context holds the lock - poll until token appears.
        set MAX_POLLS [expr { int($TIMEOUT / $POLL_INTERVAL) }]
        set POLLS 0

        while { $POLLS < $MAX_POLLS } {
            after $POLL_INTERVAL

            set CACHED_TOKEN [call /Common/MIDEYE_SHIELD_COMMON::_TBL_GET "token"]
            set TOKEN_EXP    [call /Common/MIDEYE_SHIELD_COMMON::_TBL_GET "token_exp"]

            if { $CACHED_TOKEN ne "" && $TOKEN_EXP ne "" } {
                if { ($TOKEN_EXP - $SAFEGUARD) > [call /Common/MIDEYE_SHIELD_COMMON::_GET_EPOCH] } {
                    return $CACHED_TOKEN
                }
            }

            incr POLLS
        }

        # Timed out waiting for the owning context to complete the fetch.
        return ""
    }

    # We own the lock (LOCK_RESULT was empty). Perform the token fetch.
    set BODY "grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}"

    set REQUEST_OPTS [list \
        method  "POST" \
        url     "${BASE_URL}${TOKEN_PATH}" \
        headers [list "Content-Type" "application/x-www-form-urlencoded"] \
        body    $BODY \
        timeout $TIMEOUT \
    ]

    # Perform the sideband token request via HSSR.
    if { [catch { set RESPONSE [call /Common/HSSR::request $REQUEST_OPTS] } ERR] } {
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL "token_fetching"
        return ""
    }

    # HSSR returns a two-element list: {status body}
    set STATUS    [lindex $RESPONSE 0]
    set RESP_BODY [lindex $RESPONSE 1]

    if { $STATUS != 200 } {
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL "token_fetching"
        return ""
    }

    # Extract the access_token value from the JSON response body.
    # The pattern matches: "access_token" : "< captured value >"
    if { ![regexp {"access_token"\s*:\s*"([^"]+)"} $RESP_BODY -> NEW_TOKEN] } {    #" <-- syntax highlighting WO
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL "token_fetching"
        return ""
    }

    # Parse the exp claim from the token so we honour the server-issued lifetime.
    set EXP [call /Common/MIDEYE_SHIELD_COMMON::_PARSE_JWT_EXP $NEW_TOKEN]

    if { $EXP == 0 } {
        # Could not parse exp - fall back to a conservative 5-minute cache.
        set EXP [expr { [call /Common/MIDEYE_SHIELD_COMMON::_GET_EPOCH] + 300 }]
    }

    # Cache the token and its expiry using the remaining token lifetime as TTL.
    set TTL [expr { $EXP - [call /Common/MIDEYE_SHIELD_COMMON::_GET_EPOCH] }]

    call /Common/MIDEYE_SHIELD_COMMON::_TBL_SET "token"     $NEW_TOKEN $TTL indefinite
    call /Common/MIDEYE_SHIELD_COMMON::_TBL_SET "token_exp" $EXP       $TTL indefinite

    # Release the lock so a future expiry triggers a fresh fetch.
    call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL "token_fetching"

    return $NEW_TOKEN
}

# ---------------------------------------------------------------------------
# proc: _FETCH_IP_SCORE
#
# Call the Shield API to get a score for the given IP address.
# Manages the pending-connections counter and the score sentinel (-1).
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
    set SAFE_IP       [call /Common/MIDEYE_SHIELD_COMMON::_SANITIZE_IP_KEY $client_ip]
    set SCORE_KEY     "score_${SAFE_IP}"
    set PEND_KEY      "pending_${SAFE_IP}"
    set TIMEOUT       [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_timeout"]
    set PENDING_MAX   [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "pending_max"]
    set POLL_INTERVAL [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "pending_poll_interval"]
    set BASE_URL      [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_base_url"]
    set SCORE_PATH    [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_score_path"]

    # Atomically increment the pending counter for this IP.
    # The first caller gets 1 and is elected as the API caller.
    # All subsequent callers get a higher value and become waiters.
    set PEND_VAL [table incr -subtable "MIDEYE_SHIELD" $PEND_KEY]

    if { $PEND_VAL == 1 } {
        # We are the first caller - set TTLs and write the investigation sentinel.
        # The pending key TTL is tied to api_timeout so it self-clears on crash.
        set TIMEOUT_SECS [expr { int($TIMEOUT / 1000) + 5 }]
        table set -subtable "MIDEYE_SHIELD" $PEND_KEY 1 $TIMEOUT_SECS indefinite
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_SET $SCORE_KEY -1 $TIMEOUT_SECS indefinite

        set TOKEN [call /Common/MIDEYE_SHIELD_COMMON::_GET_VALID_TOKEN]

        if { $TOKEN eq "" } {
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL $SCORE_KEY
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
            call /Common/MIDEYE_SHIELD_COMMON::_MARK_API_DOWN
            return -2
        }

        set REQUEST_OPTS [list \
            method  "GET" \
            url     "${BASE_URL}${SCORE_PATH}?ip=${client_ip}" \
            headers [list "Authorization" "Bearer ${TOKEN}"] \
            timeout $TIMEOUT \
        ]

        if { [catch { set RESPONSE [call /Common/HSSR::request $REQUEST_OPTS] } ERR] } {
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL $SCORE_KEY
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
            call /Common/MIDEYE_SHIELD_COMMON::_MARK_API_DOWN
            return -2
        }

        # HSSR returns a two-element list: {status body}
        set STATUS    [lindex $RESPONSE 0]
        set RESP_BODY [lindex $RESPONSE 1]

        if { $STATUS != 200 } {
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL $SCORE_KEY
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
            call /Common/MIDEYE_SHIELD_COMMON::_MARK_API_DOWN
            return -2
        }

        # Parse the score integer from the JSON response body.
        # Pattern matches: "score" : <digits>
        if { ![regexp {"score"\s*:\s*(\d+)} $RESP_BODY -> SCORE] } {
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL $SCORE_KEY
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY
            call /Common/MIDEYE_SHIELD_COMMON::_MARK_API_DOWN
            return -2
        }

        # Write the resolved score to cache and release the pending key.
        # Use the cache_time supplied by the caller (connection vs login TTL).
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_SET $SCORE_KEY $SCORE $cache_time indefinite
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_DEL $PEND_KEY

        call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_api_success"
        return $SCORE

    } else {
        # We are a waiter. Reject immediately if the queue is already full.
        if { $PEND_VAL > $PENDING_MAX } {
            # Release our slot with an atomic decrement before returning.
            table incr -subtable "MIDEYE_SHIELD" $PEND_KEY -1
            return -3
        }

        # Poll the score key until it resolves, is deleted, or we time out.
        set MAX_POLLS [expr { int($TIMEOUT / $POLL_INTERVAL) }]
        set POLLS 0

        while { $POLLS < $MAX_POLLS } {
            after $POLL_INTERVAL

            set CACHED_SCORE [call /Common/MIDEYE_SHIELD_COMMON::_TBL_GET $SCORE_KEY]

            # A real score (not the -1 sentinel) means the fetcher succeeded.
            if { $CACHED_SCORE ne "" && $CACHED_SCORE != -1 } {
                table incr -subtable "MIDEYE_SHIELD" $PEND_KEY -1
                return $CACHED_SCORE
            }

            # Empty key means the fetcher deleted it due to an API failure.
            if { $CACHED_SCORE eq "" } {
                table incr -subtable "MIDEYE_SHIELD" $PEND_KEY -1
                return -2
            }

            incr POLLS
        }

        # Timed out waiting for the fetcher - treat as API failure.
        table incr -subtable "MIDEYE_SHIELD" $PEND_KEY -1
        return -2
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
    set DISABLED            [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "disabled"]
    set DRY_RUN             [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "dry_run"]
    set HARD_DENY_THRESHOLD [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "score_hard_deny"]
    set WARN_THRESHOLD      [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "score_warn"]

    call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_requests"

    # Disabled flag short-circuits everything - no logging, no checks.
    if { $DISABLED eq "1" } {
        return 1
    }

    # Clean up the IP from potential Route Domain
    set client_ip [lindex [split $client_ip "%"] 0]

    # --- Blacklist check (highest priority) ---
    if { [class match $client_ip equals MIDEYE_SHIELD_BLACKLIST] } {
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_blacklisted"

        log local0.info "IP '$client_ip' DENIED due to blacklist match"
        return 0
    }

    # --- Whitelist check ---
    if { [class match $client_ip equals MIDEYE_SHIELD_WHITELIST] } {
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_whitelisted"
        return 1
    }

    # --- Cache check ---
    set SAFE_IP   [call /Common/MIDEYE_SHIELD_COMMON::_SANITIZE_IP_KEY $client_ip]
    set SCORE_KEY "score_${SAFE_IP}"
    set CACHED    [call /Common/MIDEYE_SHIELD_COMMON::_TBL_GET $SCORE_KEY]

    if { $CACHED ne "" && $CACHED != -1 } {
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_cache_hits"
        set SCORE $CACHED

    } else {
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_cache_misses"

        # If the API is known to be down, fail open immediately.
        if { [call /Common/MIDEYE_SHIELD_COMMON::_IS_API_DOWN] } {
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_allowed_apifail"
            return 1
        }

        # Fetch the score - handles pending counter and wait logic internally.
        # Pass cache_time so the fetcher caches with the correct TTL.
        set SCORE [call /Common/MIDEYE_SHIELD_COMMON::_FETCH_IP_SCORE $client_ip $cache_time]

        # Pending queue for this IP is full - treat as a hard deny.
        if { $SCORE == -3 } {
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_blocked"

            if { $DRY_RUN eq "1" } {
                log local0.warning "DRY RUN - Would have denied IP due to too many pending conenctions from '$client_ip'"
                return 1
            }

            return 0
        }

        # API failure or timeout waiting for a score - fail open.
        if { $SCORE == -2 } {
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_api_fail"
            call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_allowed_apifail"
            return 1
        }
    }

    # --- Score evaluation ---
    if { $SCORE >= $HARD_DENY_THRESHOLD } {
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_blocked"

        if { $DRY_RUN eq "1" } {
            log local0.warning "DRY RUN - Would have denied '$client_ip' due to high score of '$SCORE'"
            return 1
        }

        log local0.info "DENY '$client_ip' due to too high score '$SCORE'"
        return 0
    }

    if { $SCORE >= $WARN_THRESHOLD } {
        call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_allowed_score"
        log local0.warning "WARNING '$client_ip' score '$SCORE' is inside the warn band"
        return 1
    }

    call /Common/MIDEYE_SHIELD_COMMON::_TBL_INCR "stat_allowed_score"
    return 1
}

# ===========================================================================
# P U B L I C   P R O C E D U R E S
# ===========================================================================

# ---------------------------------------------------------------------------
# proc: VALIDATE_CONNECTION
#
# Validates an IP at the TCP connection level. Uses score_cache_time from
# settings as the cache TTL, which is typically a longer value (e.g. 300s).
#
# Returns 1 to allow, 0 to reject.
#
#   if { ![call /Common/MIDEYE_SHIELD_COMMON::VALIDATE_CONNECTION [IP::client_addr]] } {
#       reject
#   }
# ---------------------------------------------------------------------------
proc VALIDATE_CONNECTION { client_ip } {
    set CACHE_TIME [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "score_cache_time"]
    return [call /Common/MIDEYE_SHIELD_COMMON::_VALIDATE $client_ip $CACHE_TIME]
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
#   if { ![call /Common/MIDEYE_SHIELD_COMMON::VALIDATE_LOGIN [IP::client_addr]] } {
#       reject
#   }
# ---------------------------------------------------------------------------
proc VALIDATE_LOGIN { client_ip } {
    set CACHE_TIME [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "login_score_cache_time"]
    return [call /Common/MIDEYE_SHIELD_COMMON::_VALIDATE $client_ip $CACHE_TIME]
}

# ---------------------------------------------------------------------------
# proc: REPORT_AUTH_RESULT
#
# Report an authentication result for an IP back to the Shield API.
#
# Called from the APM iRule after ACCESS_POLICY_COMPLETED.
# auth_result must be "allow" or "deny".
# This is fire-and-forget - errors are logged but never propagated.
# ---------------------------------------------------------------------------
proc REPORT_AUTH_RESULT { client_ip auth_result } {
    set BASE_URL    [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_base_url"]
    set REPORT_PATH [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_report_path"]
    set TIMEOUT     [call /Common/MIDEYE_SHIELD_COMMON::_DG_GET "api_timeout"]

    set TOKEN [call /Common/MIDEYE_SHIELD_COMMON::_GET_VALID_TOKEN]

    if { $TOKEN eq "" } {
        log local0.warning "REPORT_AUTH_RESULT - No valid API token, skipping report for '$client_ip'"
        return
    }

    set BODY "{\"ip\":\"${client_ip}\",\"auth_result\":\"${auth_result}\"}"

    set REQUEST_OPTS [list \
        method  "POST" \
        url     "${BASE_URL}${REPORT_PATH}" \
        headers [list \
            "Authorization" "Bearer ${TOKEN}" \
            "Content-Type"  "application/json" \
        ] \
        body    $BODY \
        timeout $TIMEOUT \
    ]

    # Fire and forget - catch but discard any error.
    catch { call /Common/HSSR::request $REQUEST_OPTS }
}

# ---------------------------------------------------------------------------
# proc: GET_STATS
#
# Return a flat {key value key value ...} list of all statistics counters.
# Callers iterate it with:
#   foreach {K V} [call /Common/MIDEYE_SHIELD_COMMON::GET_STATS] { ... }
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
        set VAL [call /Common/MIDEYE_SHIELD_COMMON::_TBL_GET $KEY]

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
