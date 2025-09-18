#!/bin/bash
cd /home/knot

if [ $# -ne 1 ]
  then
    echo "needs 1 argument supplied"
    echo "zone name"
    exit
fi
echo Unaking DM Configuration for $1
# $1 is zone name

# new DB based code to unmake an existing delegate zone under homenetdns.com
# can be adapted later to have multiple parent zones if needed

# start a zone change to remove delegate the zone from our parent
knotc zone-begin "homenetdns.com"
# add NS records for the delegation
knotc zone-unset "homenetdns.com" "$1." 3600 NS ns1.homenetinfra.com.
knotc zone-unset "homenetdns.com" "$1." 3600 NS ns2.homenetinfra.com.
# commit the zone change
knotc zone-commit "homenetdns.com"

# start config change
knotc conf-begin

# disassociates a file
# covered by default template
#knotc conf-unset "zone[$1].file" "/home/knot/zones/$1.zone"

# unconfig our master for axfr, which is the HNA
#knotc conf-unset remote["hna_$1"].address $2
knotc conf-unset "zone[$1].master" "hna_$1"
knotc conf-unset remote.id "hna_$1"

# notify our secondary
# covered by default template
#knotc conf-unset "zone[$1].notify" ns2.homenetinfra.com

# unapply ACLs
knotc conf-unset "zone[$1].acl" acl_homenetinfra.com acl_$1

# turn off zone signing. That's done for us by the HNA
# covered by default template
#knotc conf-unset "zone[$1].dnssec-signing" off

# unlink the template: destroys the 2ndary
knotc conf-unset zone[$1].template m1

# destroy the zone
knotc conf-unset zone.domain $1

# destroy an ACL so HNA can notify
#knotc conf-unset acl[acl_$1].action transfer notify
#knotc conf-unset acl[acl_$1].address $2
knotc conf-unset acl.id "acl_$1"
# commit the new config
knotc conf-commit

# remove the zone file
if [ -e "/home/knot/zones/$1.zone" ]
  then
    echo "removing file" "/home/knot/zones/$1.zone"
    rm "/home/knot/zones/$1.zone"
fi


exit 0

echo /usr/local/sbin/knotc -t 10 -b -c /usr/local/etc/knot-dm/knot.conf reload
/usr/local/sbin/knotc -v -t 10 -b -c /usr/local/etc/knot-dm/knot.conf reload

echo Making Slave Config
/usr/bin/ssh ray@92.111.140.210 ~ray/make_knot_slave_config.bash $1
