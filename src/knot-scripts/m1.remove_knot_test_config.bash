#!/usr/bin/bash
knotc zone-begin example.com
knotc zone-unset example.com  @ 3600 SOA  ns admin 1 86400 900 691200 3600
knotc zone-unset example.com example.com. 600 NS ns1.homenetinfra.com.
knotc zone-unset example.com example.com. 600 NS ns2.homenetinfra.com.
knotc zone-commit example.com
knotc zone-sign example.com
knotc zone-flush

knotc conf-begin
knotc conf-unset zone[example.com]
knotc conf-commit


