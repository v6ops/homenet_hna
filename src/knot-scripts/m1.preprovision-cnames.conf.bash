#!/bin/bash
# set up cnames in the base homenetdns.com zone
#
# this cname is used for sub-zone registration and points to the dm
# the dm synthesizes the dynamic dns updates and responses
# expected by Let's Encrypt.
# The cnames are inserted as a batch in advance to avoid overloading
# the DNS infra and triggering frequent zone resigning and AXFR.
#
# run every preprovision time slot on the PRIMARY NS
#

# read 1024 words from file
# feel fee to change the language
# kudos to https://github.com/pera/simple1024/blob/master/wordlist.txt
i=0
words=()
while read -r line
do
  words[${i}]="$line"
  i=$(( $i + 1))
done < 1024words.txt

if [[ $i -ne 1024 ]] 
then
  echo "Error: need 1024 words to create names."
  exit 0
fi


function create_zone_name () {

  #concat some random text onto the predictable counter
  local input="$1somesecrettext"

  # create seed for new opaque but invariant zone name using hash
  local seed=`echo $input|sha256sum|awk '{print $1;}'`
  local zone_name=""
  # zone name is 4 words
  for k in $(seq 1 4)
    do
    # take 3 hex chars (12 bits) and convert to a word (10 bits)
    local tmp=`echo ${seed} | head -c $((${k}*3)) | tail -c 3`
    # convert to decimal
    local tmp2=$((16#$tmp))
    #local tmp2=`echo $((16#$tmp))`
    # mod 1024
    local tmp2=$(( $tmp2 - ($tmp2 / 1024) * 1024 ))
    # add the word onto the zone name
    local zone_name="${zone_name}${words[$tmp2]}."
  done
  echo "$zone_name"
}

# abort any hanging transaction
knotc zone-abort homenetdns.com

# work out the provisioning time_slot
# every minute
slot=60
# time now in seconds since 1970
t=`date +%s`
# round up to the beginning of the next slot
# so cnames are made well in advance and synched over the infra
t=$(( $t / $slot * $slot + $slot ))
echo "Next timeslot starts at: $t"

knotc zone-begin homenetdns.com
echo "set"
# make 1000 cnames
start=1000
end=1099
time for i in $(seq $start $end);
do {
  #concat the slot_time and the counter
  c="${t}${i}"
  z="$(create_zone_name $c)"
  #echo $z
  # create the cname for <zone>.homenetdns.com -> <zone>.acme.homenetinfra.com
  knotc zone-set homenetdns.com "_acme-challenge.${z}homenetdns.com." 300 CNAME _acme-challenge.${z}acme.homenetinfra.com. >/dev/null

}
done

echo "unset"
# destroy old cnames between 3 and 5 slots back
# gives the cert authority a 2 full slots to complete cert generation
time for j in $(seq 0 2 );
do {
  old=$(( $t - $slot * $j ))
  for i in $(seq $start $end);
  do {
    #concat the old slot_time and the counter
    c="${old}${i}"
    # create the old zone name
    z="$(create_zone_name $c)"
    # destroy the old cname for <zone>.homenetdns.com -> <zone>.acme.homenetinfra.com
   knotc zone-unset homenetdns.com "_acme-challenge.${z}homenetdns.com." 300 CNAME _acme-challenge.${z}acme.homenetinfra.com. >/dev/null
  }
  done
}
done

echo "exec"
time knotc zone-commit homenetdns.com

