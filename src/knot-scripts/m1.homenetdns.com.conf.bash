#!/bin/bash
# set up the base homenetdns.com zone
#
# this is the zone also has full DS delegation from the registrar
# but the NS is provided by homenetinfra.com
#
# only needs run once at setup on the MASTER NS
# run after homenetinfra zone has been set up
#

knotc -b conf-begin
# create the homenetinfra.net domain
knotc -b conf-unset 'zone[homenetdns.com]'
knotc -b conf-commit
knotc -b conf-begin
knotc -b conf-set 'zone[homenetdns.com]'
# turn on automatic signing
knotc -b conf-set 'zone[homenetdns.com].dnssec-signing' on
# our file storage for this zone
knotc -b conf-set 'zone[homenetdns.com].file' /home/knot/zones/homenetdns.com.zone
#knotc -b conf-set 'zone[homenetdns.com].notify' ns1.homenetinfra.com.
# notify our secondary
knotc -b conf-set 'zone[homenetdns.com].notify' ns2.homenetinfra.com.
# allow the axfr from the secondary
knotc -b conf-set 'zone[homenetdns.com].acl' acl_homenetinfra.com
knotc -b conf-commit
sleep 1

knotc -b zone-freeze homenetdns.com
knotc -b zone-begin homenetdns.com.
knotc -b zone-set homenetdns.com. @ 600 SOA ns1.homenetinfra.com. hostmaster.globis.net. 2025112603 3600 1800 604800 604800
knotc -b zone-set homenetdns.com. @ 600 NS ns1.homenetinfra.com.
knotc -b zone-set homenetdns.com. @ 600 NS ns2.homenetinfra.com.
knotc -b zone-commit homenetdns.com
knotc -b zone-thaw homenetdns.com
knotc -b zone-flush homenetdns.com
