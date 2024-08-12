#!/bin/bash
#
# Script to help you run fwtrash.py
#-----------------------------------

#
LOG="/var/log/nginx/access.log"
#
if [[ $(cat $LOG | wc -l) == "0" ]]; then
	echo "Log file $LOG is empty, exiting.";
	exit
fi
#
tail -f $LOG | ./fwtrash.py -D -P rules/http.rules -a allowedips.txt -o badips.out -O trash_http.out -p modules.http -s "date,ip,repeat,blocked,bruteforced,req;40,ref;10,ua;10,code,len" -S "[--DATE] - ([--REPEAT],[--CODE],[--LEN],[--BLOCKED],[--BRUTEFORCED]) [--IP] => [--REQ] ua: [--UA], ref: [--REF]" -c "iptables -A INPUT -s [--IP]/32 -j DROP" -b "key:1,climit:3,tlimit:5;key:2,climit:3,tlimit:6"
