#!/bin/bash
# set up the base homenetinfra.com zone
#
# this is the zone that had full DS delegation from the registrar
# and hosts all our infra
#
# only needs run once at setup on the SECONDARY NS
#

knotc conf-begin
# set up some addresses for later use
knotc conf-set remote.id ns1.homenetinfra.com
knotc conf-set remote[ns1.homenetinfra.com].address 2a01:239:24f:f800::1
knotc conf-set remote.id ns2.homenetinfra.com
knotc conf-set remote[ns2.homenetinfra.com].address 2a02:247a:21e:4e00::1

# an ACL containing our servers
knotc conf-set acl.id acl_homenetinfra.com
knotc conf-set acl[acl_homenetinfra.com].address 2a01:239:24f:f800::1 85.215.139.146 2a02:247a:21e:4e00::1  212.132.88.195
# allow all our own servers to notify and axfr
knotc conf-set acl[acl_homenetinfra.com].action transfer notify

knotc conf-commit

knotc conf-begin
# set up a default template
# note templates aren't nested so this includes all defaults
knotc conf-set template.id default
knotc conf-set template[default].dnssec-signing off
knotc conf-set template[default].acl acl_homenetinfra.com
# primary
#knotc conf-set template[default].notify ns2.homenetinfra.com
## secondary
knotc conf-set template[default].master ns1.homenetinfra.com
knotc conf-set template[default].storage /home/knot
knotc conf-set template[default].file zones/%s.zone
knotc conf-set template[default].zonefile-load difference
knotc conf-set template[default].serial-policy unixtime
knotc conf-commit

knotc conf-begin
# create the homenetinfra.net domain
knotc conf-set zone.domain homenetinfra.com
# turn on automatic signing
knotc conf-set zone[homenetinfra.com].dnssec-signing on
# our file storage for this zone
knotc conf-set zone[homenetinfra.com.].file /home/knot/zones/homenetinfra.com.zone
# notify our secondary
#knotc conf-set zone[homenetinfra.com].notify ns2.homenetinfra.com
# set up our primary
knotc conf-set zone[homenetinfra.com].master ns1.homenetinfra.com
# allow the notify from the primary or axfr from the secondary
knotc conf-set zone[homenetinfra.com].acl acl_homenetinfra.com

knotc conf-commit
