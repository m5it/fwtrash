#!/bin/bash
# script to clear badips from iptables
#-------------------------------------
#iptables -D INPUT -s $(iptables -L -n | awk '/DROP/{print $4}')/32 -j DROP
for ip in $(iptables -L -n | awk '/DROP/{print $4}'); do
    #echo "ip: "$ip
    iptables -D INPUT -s $ip -j DROP
done
