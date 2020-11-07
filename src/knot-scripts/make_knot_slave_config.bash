#!/bin/bash
cd /etc/knot
if [ $# -ne 1 ]
  then
    echo "needs 1 argument"
    echo "zone name"
    exit
fi
echo Making slave Configuration for $1
# $1 is zone name
echo "acl:" >./additional_conf/$1.conf
echo "  - id: acl_$1" >>./additional_conf/$1.conf
echo "    address: [92.111.140.208/29, 2001:470:1f15:62e:21c::/64]">>./additional_conf/$1.conf
echo "    action:  [transfer,notify]">>./additional_conf/$1.conf
echo "remote:" >>./additional_conf/$1.conf
echo "  - id: ns1_$1" >>./additional_conf/$1.conf
echo "    address: 2001:470:1f15:62e:21c:c4ff:fec9:de16" >>./additional_conf/$1.conf

echo "zone:" >>./additional_conf/$1.conf
echo "  - domain: $1" >>./additional_conf/$1.conf
echo "    master: ns1_$1" >>./additional_conf/$1.conf
echo "    acl: acl_$1" >>./additional_conf/$1.conf

echo Reloading

/sbin/knotc -c /etc/knot/knot.conf reload
