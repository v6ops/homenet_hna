#!/bin/bash
knotc conf-begin

# set up a catalogue zone catz. for receiving new zones to the 2ndary
# the 2ndary builds config for the new zone
#
# only needs run once at setup ON THE SECONDARY NS
#
# set up a template for the destination zones
# note templates aren't nested so this includes all defaults
knotc conf-set template.id s2
# HNA is the signer
knotc conf-set template[s2].dnssec-signing off
# allow notify from the master
knotc conf-set template[s2].acl acl_homenetinfra.com
# primary is the master for the new zone
knotc conf-set template[s2].master ns1.homenetinfra.com
knotc conf-set template[s2].storage /home/knot
knotc conf-set template[s2].file zones/%s.zone
knotc conf-set template[s2].zonefile-load difference
knotc conf-set template[s2].serial-policy unixtime
knotc conf-commit

# create the catalog zone
knotc conf-begin
knotc conf-set zone.domain catz.
# secondary interprets the catalogue
knotc conf-set zone[catz.].catalog-template s2
knotc conf-set zone[catz.].catalog-role interpret
# allow notify for the catalog zone itself
knotc conf-set zone[catz.].acl acl_homenetinfra.com
# set the master for the catz zone
knotc conf-set zone[catz.].master ns1.homenetinfra.com
knotc conf-commit
