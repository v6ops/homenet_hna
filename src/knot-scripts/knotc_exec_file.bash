#!/bin/bash
# exec gthe knotc commands contained in file
# cd /usr/local/etc/knot-dm
if [ $# -ne 1 ]
  then
    echo "needs 1 argument supplied"
    echo "file name"
    exit -1
fi

echo $1
# check for a simple alphanumeric filename with dots
if [[ $1 =~  ^[a-zA-Z0-9\.\/]+$ ]]
then
    echo "file name is OK"
    knotc -C /var/lib/knot/confdb -t 30 -b < $1
    exit 0
else
    echo "file name is too complex"
    exit -1
fi
