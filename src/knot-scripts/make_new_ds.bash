#!/bin/bash
cd /usr/local/etc/knot-dm/zones
if [ $# -ne 1 ]
  then
    echo "needs 1 argument supplied"
    echo "DS RR"
    exit
fi
echo "Making $1"
knotc -c /usr/local/etc/knot-dm/knot.conf zone-begin homenetdns.com
knotc -c /usr/local/etc/knot-dm/knot.conf zone-set homenetdns.com $1
knotc -c /usr/local/etc/knot-dm/knot.conf zone-commit homenetdns.com
