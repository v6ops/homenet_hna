#!/bin/bash
cd /usr/local/etc/knot
if [ $# -lt 3 ]
  then
    echo "needs 3 arguments supplied"
    echo "zone name, notify address, axfr acl range"
    exit
fi
echo Making Configuration for $1 $2 $3
# $1 is zone name
# $2 is the notify address
# $3 is the acl for the axfr

echo "acl:" >./additional_conf/$1.conf
echo "  - id: acl_$1" >>./additional_conf/$1.conf
echo "    address: $3" >>./additional_conf/$1.conf
echo "    action:  transfer" >>./additional_conf/$1.conf
echo "" >>./additional_conf/$1.conf
echo "remote:" >>./additional_conf/$1.conf
echo "  - id: dm_$1" >>./additional_conf/$1.conf
echo "    address: $2" >>./additional_conf/$1.conf
echo "" >>./additional_conf/$1.conf
echo "zone:" >>./additional_conf/$1.conf
echo "  - domain: $1" >>./additional_conf/$1.conf
echo "    notify: dm_$1" >>./additional_conf/$1.conf
echo "    acl: acl_$1" >>./additional_conf/$1.conf

echo Making Initial Zone for $1 $2
cat ./templates/$1.zone >./zones/$1.zone
cat ./templates/additional_rr.zone >>./zones/$1.zone

echo Reloading and signing

/usr/local/sbin/knotc -c /usr/local/etc/knot/knot.conf reload
/usr/local/sbin/keymgr -c /usr/local/etc/knot/knot.conf $1 ds >./ds/ds.$1.zone 2>&1

