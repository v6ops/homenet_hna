#!/bin/bash
# delete (unset) TXT RR for a (to be) delegated zone in parent. Used after DNS ACME challenge completed
# zone-unset zone owner [type [rdata]]
# Remove zone data within the transaction.
cd /usr/local/etc/knot-dm/zones
if [ $# -ne 2 ]
  then
    echo "needs 2 arguments supplied"
    echo "zone name"
    echo "TXT RR data (ACME challenge)"
    exit
fi
knotc -c /usr/local/etc/knot-dm/knot.conf zone-begin homenetdns.com
knotc -c /usr/local/etc/knot-dm/knot.conf zone-unset homenetdns.com $1 TXT $2
knotc -c /usr/local/etc/knot-dm/knot.conf zone-commit homenetdns.com
