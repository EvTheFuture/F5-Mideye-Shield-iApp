#== HSSR-Helper for Mark's HTTP Super SIDEBAND Requestor! (v2.1) ======
#
# Save this iRule in the Common partition under the name 'HSSR-helper'.
#
# You will use this iRule '/Common/HSSR-helper' along with iRule proc
# '/Common/HSSR::http_req' (the HTTP Super SIDEBAND Requestor v2.1) to
# greatly simplify access from your own iRules to arbitrary http and
# https resources.
#
# To make a SIDEBAND connection to a TLS-guarded service you need a
# helper virtual server (at least through TMOS 11.5).
#
# Configure your helper virtual server (say, "/Common/vs-HSSR-helper")
# with a suitable Server SSL Profile, an HTTP Profile, and either
# SNAT-Automap or a SNAT Pool.  Attach this iRule to the virtual server.
# Give your helper virtual server a non-routeable virtual IP address
# and non-standard port (say, 192.0.2.2:50002)--you don't want any
# accidental non-SIDEBAND connections to it.  Do not configure any pool.
# Do not apply any Client SSL Profile.
#
# When you call /Common/HSSR::http_req to send web requests to servers
# off your BIG-IP, set -virt to your helper virtual server.  E.g.,
# [call /Common/HSSR::http_req -virt /Common/vs-HSSR-helper -uri ...]
#
# The "HSSR::http_req" proc will add an "X-HSSR-Helper" header to each
# of its outbound requests.  This iRule will read (and elide) that
# header, then use the 'node' command (and possibly an 'SSL' command)
# to connect each request to the proper server (supporting persistent
# HTTP 1.1 connections in normal fashion).
#
# (Yes, we could build a full HTTP proxy to handle this.  That would
# be overkill for our purposes.)
#

when RULE_INIT {
 #shall we emit debug messages?
 set static::HSSR_helper_debug false
}

when CLIENT_ACCEPTED {
 set h ""
 set prevdest [list]
 set dest [list]
 set v [list]
}

when HTTP_REQUEST {
 regexp {^[^\x5b:][^:]*} [HTTP::header value Host] h

 if {[set v [HTTP::header value X-HSSR-Helper]] ne ""} {
  HTTP::header remove X-HSSR-Helper

  if {$static::HSSR_helper_debug} {
   log local0.info "prevdest='${prevdest}', h='${h}', v='${v}'"
  }

  #NB: before comparing lists as strings you must be
  #very, very careful about canonical format (and in
  #the other iRule too)

  set dest [lrange $v 0 2]
  if {$dest ne $prevdest} {
   LB::detach
   if {[string index [lindex $dest 0] end] eq "s"} {
    SSL::enable serverside
   } else {
    SSL::disable serverside
   }

   if {$static::HSSR_helper_debug} {
    log local0.info "selecting node [lrange $dest 1 2] for [lrange $v 3 4] to '${h}'"
   }
   if {[catch {node [lindex $dest 1] [lindex $dest 2]} err]} {
    log local0.err "'node' command failed ($err) while selecting node [lrange $dest 1 2] for [lrange $v 3 4] to '${h}'"

    HTTP::respond 502 Connection close
   }
  }

  set prevdest $dest
 }
}

when LB_FAILED {
 if {[catch {LB::status} lbstatus]} { set lbstatus "unknown" }
 log local0.err "cannot connect to node [lrange $dest 1 2] for [lrange $v 3 4] to '${h}', LB::status is '${lbstatus}'"

 HTTP::respond 502 Connection close
}

when SERVERSSL_CLIENTHELLO_SEND {
 #shamelessly derived from Kevin Stewart's admirable work:
 #https://devcentral.f5.com/questions/regular-ssl-tls-for-user-connections-to-the-ltm-with-sni-support-from-ltm-to-the-real-webservers

 if {$h ne ""} {
  set k [string length $h]
  set bin [binary format S1S1S1S1ca* 0 [expr {$k + 5}] [expr {$k + 3}] 0 $k $h]
  SSL::extensions insert $bin
 }
}
