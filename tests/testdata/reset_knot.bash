#!/usr/bin/bash
knotc conf-begin
knotc conf-unset 'zone[example.com]'
knotc conf-set 'zone[example.com]'
knotc conf-set 'zone[example.com].file' '/home/knot/zones/example.com'
knotc conf-set zone[example.com].notify ns2.homenetinfra.com
knotc conf-set zone[example.com].acl acl_homenetinfra.com
knotc conf-set zone[example.com].dnssec-signing on
knotc conf-commit
sleep 1
knotc zone-begin example.com
knotc zone-set example.com  @ 3600 SOA  ns admin 1 86400 900 691200 3600
knotc zone-set example.com @ 600 NS ns1.homenetinfra.com.
knotc zone-set example.com @ 600 NS ns2.homenetinfra.com.
knotc zone-commit example.com
knotc zone-sign example.com
knotc zone-flush

