# =============================================================================
# iRule   : MIDEYE_SHIELD_CONNECT
# Version : 0.9.2
# Author  : Magnus Sandin, Valitron AB
# Date    : 2026-05-18
#
# Purpose
# -------
# This iRule enforces Mideye Shield IP validation at the TCP connection level.
# It intercepts every inbound connection attempt and delegates the allow/deny
# decision entirely to MIDEYE_SHIELD_COMMON::VALIDATE_IP.
#
# This iRule must be applied to any Virtual Server that should be protected.
#
#
# Description
# -----------
# The CLIENT_ACCEPTED event fires as early as possible in the connection
# lifecycle, before any application data is exchanged. Rejecting here is the
# most efficient point to block unwanted traffic.
#
# All scoring logic, caching, blacklist/whitelist evaluation, API calls, and
# counter updates are fully encapsulated in MIDEYE_SHIELD_COMMON. This iRule
# contains no policy logic of its own.
#
#
# Dependencies - iRules (call targets)
# -------------------------------------
#   /__partition__/MIDEYE_SHIELD_COMMON
#       Must exist on the BIG-IP. Does not need to be attached to the
#       Virtual Server - library iRules are called by path reference.
#
#   __hssr_irule__  (HTTP Super Sideband Requester)
#       Must be applied to the same Virtual Server as this iRule.
#
# =============================================================================

when CLIENT_ACCEPTED {
    # Validate the connecting IP against the Shield.
    # VALIDATE_IP returns 1 to allow, 0 to reject.
    # All logging and counter updates are handled inside VALIDATE_IP.
    if { ![call /__partition__/MIDEYE_SHIELD_COMMON::VALIDATE_CONNECTION [IP::client_addr]] } {
        reject
    }
}
