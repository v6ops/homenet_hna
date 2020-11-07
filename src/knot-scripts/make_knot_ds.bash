#!/bin/bash
cd /usr/local/etc/knot
if [ $# -ne 2 ]
  then
    echo "needs 2 arguments supplied"
    echo "zone name, filename"
    exit
fi
echo Making DS for $1 $2
# $1 is zone name
# $2 is the filename

/usr/local/sbin/keymgr -c /usr/local/etc/knot/knot.conf $1 ds >$2 2>/dev/null

