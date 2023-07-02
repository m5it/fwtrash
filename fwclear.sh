#!/bin/bash

#
iptables -F
iptables -X
# nat is used by wifihub
iptables -t nat -F
iptables -t nat -X
#
iptables -t mangle -F
iptables -t mangle -X
