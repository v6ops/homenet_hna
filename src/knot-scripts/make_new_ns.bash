#!/bin/bash
cd /usr/local/etc/knot-dm/zones
if [ $# -ne 1 ]
  then
    echo "needs 1 argument supplied"
    echo "zone name"
    exit
fi
knotc -c /usr/local/etc/knot-dm/knot.conf zone-begin homenetdns.com
knotc -c /usr/local/etc/knot-dm/knot.conf zone-set homenetdns.com $1 3600 NS ns1.homenetinfra.com.
knotc -c /usr/local/etc/knot-dm/knot.conf zone-set homenetdns.com $1 3600 NS ns2.homenetinfra.com.
knotc -c /usr/local/etc/knot-dm/knot.conf zone-commit homenetdns.com
