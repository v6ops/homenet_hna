#!/bin/bash
for i in $( seq 1 500 )
do
	/home/knot/m1.preprovision-cnames.conf.bash
	sleep 30
done
