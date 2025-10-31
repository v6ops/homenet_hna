#!/bin/bash
# set up the test example.com zone
#
#
# only needs run once at setup on the SECONDARY NS
# run after homenetinfra zone has been set up

knotc conf-begin

# create the example.net domain
knotc conf-set zone.domain example.com
# our file storage for this zone
knotc conf-set zone[example.com.].file /home/knot/zones/example.com.zone
# configure our master
knotc conf-set zone[example.com].master ns1.homenetinfra.com
# allow the notify from the master
knotc conf-set zone[example.com].acl acl_homenetinfra.com

knotc conf-commit
