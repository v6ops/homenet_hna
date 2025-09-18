#!/bin/bash
# set up the base homenetdns.com zone
#
# this is the zone also has full DS delegation from the registrar
# but the NS is provided by homenetinfra.com
#
# only needs run once at setup on the SECONDARY NS
# run after homenetinfra zone has been set up

knotc conf-begin

# create the homenetinfra.net domain
knotc conf-set zone.domain homenetdns.com
# our file storage for this zone
knotc conf-set zone[homenetdns.com.].file /home/knot/zones/homenetdns.com.zone
# configure our master
knotc conf-set zone[homenetdns.com].master ns1.homenetinfra.com
# allow the notify from the master
knotc conf-set zone[homenetdns.com].acl acl_homenetinfra.com

knotc conf-commit
