#!/bin/bash

# set up basic server parameters that may not have been in /etc/knot/knot.conf
#
# only needs run once at setup on the MASTER NS
# do this first before the other config or zones are loaded
#
# create server defaults
knotc conf-begin

knotc conf-set server.rundir /run/knot
knotc conf-set server.user  knot:knot
# set listen ports
#master
knotc conf-set server.listen 2a01:239:24f:f800::1@53 85.215.139.146@53
##secondary
#server.listen 2a02:247a:21e:4e00::1@53 212.132.88.195@53
# logging
knotc conf-set log.target  syslog
knotc conf-set log[syslog].any  info
# storage in /home/knot
knotc conf-set database.storage  /home/knot
knotc conf-set keystore.id  keys
knotc conf-set keystore[keys].backend  pem
knotc conf-set policy.id  auto-sign
knotc conf-set policy[auto-sign].keystore  keys
knotc conf-set policy[auto-sign].algorithm  rsasha256
knotc conf-set policy[auto-sign].ksk-size  2048
knotc conf-set policy[auto-sign].zsk-size  1024
knotc conf-set mod-rrl.id  default
knotc conf-set mod-rrl[default].rate-limit  20
knotc conf-set mod-rrl[default].slip  2
knotc conf-commit

