# =============================================================================
# iRule   : MIDEYE_SHIELD_APM
# Version : 0.9.4
# Author  : Magnus Sandin, Valitron AB
# Date    : 2026-05-28
#
# Purpose
# -------
# This iRule integrates Mideye Shield with the BIG-IP Access Policy Manager.
# It provides two integration points within an APM access profile:
#
#   1. Before authentication - validates the connecting IP via a Validate IP
#      iRule event in the access policy, allowing the policy to gate access
#      before credentials are even processed.
#
#   2. After authentication - reports the authentication outcome back to the
#      Shield API so that it can refine future scoring for this IP.
#
# This iRule must be applied to any APM Virtual Server that should be
# protected by Mideye Shield login validation.
#
#
# Description
# -----------
# ACCESS_POLICY_AGENT_EVENT handles the event id "MIDEYE_SHIELD-VALIDATE_IP"
# triggered from within the access profile using an iRule Event agent. The event
# id is case-sensitive and the policy must match exactly this name to function.
#
# If VALIDATE_LOGIN returns 0 (deny), the session variable
# "session.custom.shield.allow" is set to 0 and the policy can branch on
# this value using a Variable Assign or Empty Ending agent. If 1 (allow),
# the variable is set to 1.
#
# Use the following branch rule to match if the IP is allowed:
# expr {[mcget session.custom.shield.allow] == 1}
#
#
# ACCESS_POLICY_COMPLETED fires after the policy has reached an ending and
# the final allow/deny decision is known. The auth result is reported to
# the Shield API as a fire-and-forget call via REPORT_AUTH_RESULT.
#
#
# Access Policy Configuration
# ---------------------------
# In the access profile, add an iRule Event agent and set the ID to:
# MIDEYE_SHIELD-VALIDATE_IP
#
# Use the following branch rule to match if the IP is allowed:
# expr {[mcget session.custom.shield.allow] == 1}
#
#
# Dependencies - iRules (call targets)
# -------------------------------------
#   /__partition__/MIDEYE_SHIELD_COMMON
#       Must exist on the BIG-IP. Does not need to be attached to the
#       Virtual Server - library iRules are called by path reference.
#
# =============================================================================

when ACCESS_POLICY_AGENT_EVENT {
    # Only act on the validate_ip event triggered from the access profile.
    set event [string toupper [ACCESS::policy agent_id]];
    if {$event == "MIDEYE_SHIELD-VALIDATE_IP"} {
        set allow [call /__partition__/MIDEYE_SHIELD_COMMON::VALIDATE_LOGIN [IP::client_addr]]
        ACCESS::session data set session.custom.shield.allow $allow

        call /__partition__/MIDEYE_SHIELD_COMMON::LOG_DEBUG "Allow status set to '$allow'"
    } elseif {$event == "MIDEYE_SHIELD-REPORT_AUTH_RESULT"} {
        # Report the final authentication outcome back to the Shield API.
        call /__partition__/MIDEYE_SHIELD_COMMON::REPORT_AUTH_RESULT [ACCESS::session data get session.user.clientip]
    }
}

when ACCESS_POLICY_COMPLETED {
    # Report the final authentication outcome back to the Shield API.
    call /__partition__/MIDEYE_SHIELD_COMMON::REPORT_AUTH_RESULT [ACCESS::session data get session.user.clientip]
}
