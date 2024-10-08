#!/bin/bash
#
# Script to help you run fwtrash.py with SSH module
#---------------------------------------------------

#
LOG="/var/log/auth.log"
#
if [[ $(cat $LOG | wc -l) == "0" ]]; then
	echo "Log file $LOG is empty, exiting.";
	exit
fi
#
tail -f $LOG | ./fwtrash.py -D -o badips.out \
-O trash_ssh.out \
-P rules/ssh.rules \
-p modules.ssh \
-s "date,ip,repeat,blocked,bruteforced,message;100" \
-S "[--DATE] [--IP]([--REPEAT],[--BLOCKED],[--BRUTEFORCED]) => [--MESSAGE]" \
-c "iptables -A INPUT -s [--IP]/32 -j DROP" \
-b "key:0,climit:3,tlimit:60;key:1,climit:3,tlimit:120"
