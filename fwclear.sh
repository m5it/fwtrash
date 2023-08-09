#!/bin/bash

#
iptables -F
iptables -X

#--
# (uncomment if you like to clean this too) -  nat is used by wifihub, docker etc...
#iptables -t nat -F
#iptables -t nat -X

#--
# (uncomment if you like to clean this too)
#iptables -t mangle -F
#iptables -t mangle -X
