#!/bin/bash
# set up the base homenetdns.com zone
#
# this is the zone also has full DS delegation from the registrar
# but the NS is provided by homenetinfra.com
#
# only needs run once at setup on the MASTER NS
# run after homenetinfra zone has been set up
#

knotc conf-begin

# create the homenetinfra.net domain
knotc conf-set zone.domain homenetdns.com
# turn on automatic signing
knotc conf-set zone[homenetdns.com].dnssec-signing on
# our file storage for this zone
knotc conf-set zone[homenetdns.com.].file /home/knot/zones/homenetdns.com.zone
#knotc conf-set zone[homenetdns.com].notify ns1.homenetinfra.com
# notify our secondary
knotc conf-set zone[homenetdns.com].notify ns2.homenetinfra.com
# allow the axfr from the secondary
knotc conf-set zone[homenetdns.com].acl acl_homenetinfra.com

knotc conf-commit

knotc zone-begin homenetdns.com
knotc zone-set homenetdns.com homenetdns.com. 600 SOA ns1.homenetinfra.com. hostmaster.globis.net. 2025102801 3600 1800 604800 604800
knotc zone-set homenetdns.com homenetdns.com. 600 NS ns1.homenetinfra.com.
knotc zone-set homenetdns.com homenetdns.com. 600 NS ns2.homenetinfra.com.

knotc zone-commit homenetdns.com
