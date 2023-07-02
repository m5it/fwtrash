#!/bin/bash

#--------------------------------------------------------------------
#                   logtrash.py by beaykos.69.mu
#                       & wanabe hackers :)
#--------------------------------------------------------------------

#
iptables -F
iptables -X
# nat is used by wifihub
#iptables -t nat -F
#iptables -t nat -X
#
iptables -t mangle -F
iptables -t mangle -X

iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

#-- nginx & sshd
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
#iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
#iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 7983 -j ACCEPT
#iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 48152 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 3306 -j ACCEPT
#iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 44969 -j ACCEPT
#-- vsftpd
#iptables -A INPUT -p tcp --dport 44969 -j ACCEPT
#iptables -A INPUT -p tcp --dport 20 -j ACCEPT
#iptables -A INPUT -p tcp --dport 30727:30737 -j ACCEPT

#-- Accept lokkal & fileserver for memcached
#-- lokkal servers
#-- File servers
# fs1.lokkal.com
#iptables -A INPUT -s 172.31.9.22 -p tcp -m state --state NEW -m tcp --dport 11211 -j ACCEPT

#--
# block https://about.censys.io/
iptables -A INPUT -s 167.248.133.0/24 -j DROP
# block all in badips.out
cat badips.out | while read ip; do
	echo "Blocking ip "$ip
	iptables -A INPUT -s $ip/32 -j DROP
done

#--
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
iptables -P INPUT DROP
