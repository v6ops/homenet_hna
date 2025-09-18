#!/bin/bash
cd /home/knot

if [ $# -ne 2 ]
  then
    echo "needs 2 arguments supplied"
    echo "zone name, remote address"
    exit
fi
echo Making DM Configuration for $1 $2
# $1 is zone name
# $2 is the remote address

# new DB based code to create a new delegate zone under homenetdns.com
# can be adapted later to have multiple parent zones if needed

# start config change
knotc conf-begin
# create an ACL so HNA can notify
knotc conf-set acl.id "acl_$1"
knotc conf-set acl[acl_$1].address $2
knotc conf-set acl[acl_$1].action transfer notify

# creates the zone
knotc conf-set zone.domain $1
# associates a file
# covered by default template
#knotc conf-set "zone[$1].file" "/home/knot/zones/$1.zone"

# set the zone template to m1, which adds it to the catalog zone catz.
# this auto-configs the secondary
knotc conf-set zone[$1].template m1

# config our master for axfr, which is the HNA
knotc conf-set remote.id "hna_$1"
knotc conf-set remote["hna_$1"].address $2
knotc conf-set "zone[$1].master" "hna_$1"

# notify our secondary
# covered by default template
#knotc conf-set "zone[$1].notify" ns2.homenetinfra.com
# apply ACLs
knotc conf-set "zone[$1].acl" acl_homenetinfra.com acl_$1

# turn off zone signing. That's done for us by the HNA
# covered by default template
#knotc conf-set "zone[$1].dnssec-signing" off
# commit the new config
knotc conf-commit

# start a zone change to delegate the zone from our parent
knotc zone-begin "homenetdns.com"
# add NS records for the delegation
knotc zone-set "homenetdns.com" "$1." 3600 NS ns1.homenetinfra.com.
knotc zone-set "homenetdns.com" "$1." 3600 NS ns2.homenetinfra.com.
# commit the zone change
knotc zone-commit "homenetdns.com"

# flush to file
knotc zone-flush "homenetdns.com"

# start a zone change to fill the zone
# populate a blank zone awaiting the HNA
knotc zone-begin "$1"
knotc zone-set "$1" @ 7200 SOA ns hostmaster 1 86400 900 691200 3600
knotc zone-set "$1" "$1." 3600 NS ns1.homenetinfra.com.
knotc zone-set "$1" "$1." 3600 NS ns2.homenetinfra.com.
# commit the zone change
knotc zone-commit "$1"

# flush to file
knotc zone-flush "$1"


exit 0

echo /usr/local/sbin/knotc -t 10 -b -c /usr/local/etc/knot-dm/knot.conf reload
/usr/local/sbin/knotc -v -t 10 -b -c /usr/local/etc/knot-dm/knot.conf reload

echo Making Slave Config
/usr/bin/ssh ray@92.111.140.210 ~ray/make_knot_slave_config.bash $1
