#!/bin/bash

while read -r L; do
	echo "L: "$L
	iptables -D INPUT -s $L -j DROP
done
