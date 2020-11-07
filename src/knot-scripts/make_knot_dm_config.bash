#!/bin/bash
cd /usr/local/etc/knot-dm
if [ $# -ne 2 ]
  then
    echo "needs 2 arguments supplied"
    echo "zone name, remote address"
    exit
fi
echo Making DM Configuration for $1 $2
# $1 is zone name
# $2 is the remote address

echo "acl:" >./additional_conf/$1.conf
echo "  - id: acl_$1" >>./additional_conf/$1.conf
echo "    address: $2" >>./additional_conf/$1.conf
echo "    action:  notify" >>./additional_conf/$1.conf
echo "" >>./additional_conf/$1.conf
echo "acl:" >>./additional_conf/$1.conf
echo "  - id: acl_parent_$1" >>./additional_conf/$1.conf
echo "    address: [92.111.140.208/29, 2001:470:1f15:62e::/64]" >>./additional_conf/$1.conf
echo "    action:  [transfer,notify]" >>./additional_conf/$1.conf
echo "remote:" >>./additional_conf/$1.conf
echo "  - id: hna_$1" >>./additional_conf/$1.conf
echo "    address: $2" >>./additional_conf/$1.conf
echo "  - id: ns1_$1" >>./additional_conf/$1.conf
echo "    address: 2001:470:1f15:62e:21c:c4ff:fec9:de16" >>./additional_conf/$1.conf
echo "  - id: ns2_$1" >>./additional_conf/$1.conf
echo "    address: 2001:470:1f15:62e:ba27:ebff:fe6c:1b38" >>./additional_conf/$1.conf
echo "" >>./additional_conf/$1.conf
echo "zone:" >>./additional_conf/$1.conf
echo "  - domain: $1" >>./additional_conf/$1.conf
echo "    master: hna_$1" >>./additional_conf/$1.conf
#echo "    notify: [ns1.homenetinfra.com,ns2.homenetinfra.com]" >>./additional_conf/$1.conf
echo "    notify: [ns1_$1,ns2_$1]" >>./additional_conf/$1.conf
echo "    acl: [acl_parent_$1,acl_$1]" >>./additional_conf/$1.conf

echo Reloading

/usr/local/sbin/knotc -c /usr/local/etc/knot-dm/knot.conf reload

echo Making Slave Config
/usr/bin/ssh ray@92.111.140.210 ~ray/make_knot_slave_config.bash $1
