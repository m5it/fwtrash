#!/bin/bash
#
# Script to help you run fwtrash.py for VSFTPD service
#-----------------------------------------------------

#tail -f /var/log/syslog.test | ./fwtrash.py -D
#cat /var/log/syslog.test | ./fwtrash.py -D 
tail -f /var/log/syslog | ./fwtrash.py -D \
-o badips.out \
-O trash_vsftp.out \
-P rules/vsftp.rules \
-p modules.vsftp \
-s "date,code,req,user,ip,repeat,blocked,bruteforced,file;100,hash" \
-S "[--DATE] [--CODE]/[--REQ] [--USER]:[--IP]([--REPEAT],[--BLOCKED],[--BRUTEFORCED]) => [--FILE] [--HASH]" \
-c "echo \"Looks we have bad [--USER] with ip: [--IP]\"" \
-b "key:0,climit:1,tlimit:120;key:1,climit:3,tlimit:120;key:2,climit:1,tlimit:1;key:3,climit:1,tlimit:1"

#-s "date,ip,repeat,blocked,bruteforced,message;100" \
#-S "[--DATE] [--IP]([--REPEAT],[--BLOCKED],[--BRUTEFORCED]) => [--MESSAGE]" \
#-c "iptables -A INPUT -s [--IP]/32 -j DROP" \
#-b "key:0,climit:3,tlimit:60;key:1,climit:3,tlimit:120"
