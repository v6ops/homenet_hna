#!/bin/bash
cd /home/knot-dm/zones
if [ $# -ne 1 ]
  then
    echo "needs 1 argument supplied"
    echo "DS RR"
    exit
fi
echo "Making $1"
# start a zone transaction in the parent zone homenetdns.com
knotc zone-begin homenetdns.com
# set the DS RR we've bene given
knotc zone-unset homenetdns.com $1
# commit the change
knotc zone-commit homenetdns.com
# flush the zone to disk
knotc zone-flush homenetdns.com
