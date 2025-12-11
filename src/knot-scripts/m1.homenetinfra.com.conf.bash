#!/bin/bash
# set up the base homenetinfra.com zone
#
# this is the zone that had full DS delegation from the registrar
# and hosts all our infra
#
# only needs run once at setup on the PRIMARY NS
#

knotc conf-begin
knotc conf-set server.identity ns1.homenetinfra.com
# set up some addresses for later use
knotc conf-set remote.id ns1.homenetinfra.com.
knotc conf-set remote[ns1.homenetinfra.com.].address 2a01:239:24f:f800::1
knotc conf-set remote.id ns2.homenetinfra.com.
knotc conf-set remote[ns2.homenetinfra.com.].address 2a01:239:3c7:c100::1

# an ACL containing our servers
# auto acl for zone transfer from known remotes
knotc conf-set server.automatic-acl on
knotc conf-set acl.id acl_homenetinfra.com
knotc conf-set acl[acl_homenetinfra.com].address 2a01:239:24f:f800::1 85.215.139.146 2a01:239:3c7:c100::1  212.132.88.195
# allow all our own servers to notify and axfr
knotc conf-set acl[acl_homenetinfra.com].action transfer notify

knotc conf-commit

knotc conf-begin
# set up a default template
# note templates aren't nested so this includes all defaults
knotc conf-set template.id default
knotc conf-set template[default].dnssec-signing off
knotc conf-set template[default].acl acl_homenetinfra.com
# master
knotc conf-set template[default].notify ns2.homenetinfra.com.
## secondary
#knotc conf-set template[default].master ns1.homenetinfra.com
knotc conf-set template[default].storage /home/knot
knotc conf-set template[default].file zones/%s.zone
knotc conf-set template[default].zonefile-load difference
knotc conf-set template[default].serial-policy unixtime
knotc conf-commit


# create the homenetinfra.net domain
knotc conf-begin
knotc -b conf-set 'zone[homenetinfra.com]'
# turn on automatic signing
knotc conf-set zone[homenetinfra.com].dnssec-signing on
# our file storage for this zone
knotc conf-set zone[homenetinfra.com].file /home/knot/zones/homenetinfra.com.zone
# notify our secondary
knotc conf-set zone[homenetinfra.com].notify ns2.homenetinfra.com.
# set up our primary
#knotc conf-set zone[homenetinfra.com].master ns1.homenetinfra.com
# allow the notify from the primary or axfr from the secondary
knotc conf-set zone[homenetinfra.com].acl acl_homenetinfra.com

knotc conf-commit

knotc -bf zone-purge homenetinfra.com
# set your own infra IPs here
knotc zone-begin homenetinfra.com
knotc zone-set homenetinfra.com homenetinfra.com. 600 SOA ns1.homenetinfra.com. hostmaster.globis.net. 2025112603 3600 1800 604800 600
knotc zone-set homenetinfra.com homenetinfra.com. 600 NS ns1.homenetinfra.com.
knotc zone-set homenetinfra.com homenetinfra.com. 600 NS ns2.homenetinfra.com.
knotc zone-set homenetinfra.com homenetinfra.com. 600 CAA 128 issue "letsencrypt.org"
knotc zone-set homenetinfra.com dm-synth.homenetinfra.com. 3600 NS dm1.homenetinfra.com.
knotc zone-set homenetinfra.com dm1.homenetinfra.com. 600 A 85.215.139.146
knotc zone-set homenetinfra.com dm1.homenetinfra.com. 600 AAAA 2a01:239:24f:f800::1
knotc zone-set homenetinfra.com dm2.homenetinfra.com. 600 A 212.132.88.195
knotc zone-set homenetinfra.com dm2.homenetinfra.com. 600 AAAA 2a01:239:3c7:c100::1
knotc zone-set homenetinfra.com ns1.homenetinfra.com. 600 A 85.215.139.146
knotc zone-set homenetinfra.com ns1.homenetinfra.com. 600 AAAA 2a01:239:24f:f800::1
knotc zone-set homenetinfra.com ns2.homenetinfra.com. 600 A 212.132.88.195
knotc zone-set homenetinfra.com ns2.homenetinfra.com. 600 AAAA 2a01:239:3c7:c100::1
knotc zone-set homenetinfra.com www.homenetinfra.com. 600 A 85.215.139.146
knotc zone-set homenetinfra.com www.homenetinfra.com. 600 AAAA 2a01:239:24f:f800::1
knotc zone-set homenetinfra.com _443._tcp.www.homenetinfra.com. 600 TLSA 2 0 1 25847D668EB4F04FDD40B12B6B0740C567DA7D024308EB6C2C96FE41D9DE218D
knotc zone-commit homenetinfra.com
