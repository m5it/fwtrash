#!/bin/bash
#--
# Script to unDROP dropped ips. If you think they are worth.
#--
# Ex.: 
#   sudo iptables -L INPUT -n | awk /DROP/'{print $4}' | sudo ./undrop.sh
#--
while read l; do
	echo "l: "$l
	iptables -D INPUT -s $l -j DROP
done
