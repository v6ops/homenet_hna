#!/bin/bash
knotc conf-begin

# set up a catalogue zone catz. for communicating new zones to the 2ndary
# adding a zone to tmeplate m1 automatically adds it to catz.
# which then triggers the 2ndary to build config for the new zone
#
# only needs run once at setup on the MASTER NS
#
# set up a template for the donor zones
# the individual zones need to have a config item
# [zone].template m1
# note templates aren't nested so this includes all defaults
knotc conf-set template.id m1
knotc conf-set template[m1].catalog-role member
knotc conf-set template[m1].catalog-zone catz.
knotc conf-set template[m1].dnssec-signing off
knotc conf-set template[m1].acl acl_homenetinfra.com
knotc conf-set template[m1].notify ns2.homenetinfra.com.
knotc conf-set template[m1].storage /home/knot
knotc conf-set template[m1].file zones/%s.zone
knotc conf-set template[m1].zonefile-load difference
knotc conf-set template[m1].serial-policy unixtime
knotc conf-commit

# create the catalog zone
knotc conf-begin
knotc conf-set zone.domain catz.
knotc conf-set zone[catz.].catalog-role generate
knotc conf-set zone[catz.].acl acl_homenetinfra.com
knotc conf-commit

