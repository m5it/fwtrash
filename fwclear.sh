#!/bin/bash
#--
# Clear DROPed ips.
#--
# Usage: 
#   sudo iptables -L INPUT -n | awk /DROP/'{print $4}' | sudo ./fwclear.sh
#--
while read -r L; do
	echo "L: "$L
	iptables -D INPUT -s $L -j DROP
done
