#!/bin/bash
# add TXT RR for a (to be) delegated zone in parent. Used for DNS ACME challenge
#  zone-set zone owner [ttl] type rdata
#  Add zone record within the transaction. The first record in a rrset requires a ttl value specified.
cd /usr/local/etc/knot-dm/zones
if [ $# -ne 2 ]
  then
    echo "needs 2 arguments supplied"
    echo "zone name"
    echo "TXT RR data (ACME challenge)"
    exit
fi
knotc -c /usr/local/etc/knot-dm/knot.conf zone-begin homenetdns.com
knotc -c /usr/local/etc/knot-dm/knot.conf zone-set homenetdns.com $1 600 TXT $2
knotc -c /usr/local/etc/knot-dm/knot.conf zone-commit homenetdns.com
