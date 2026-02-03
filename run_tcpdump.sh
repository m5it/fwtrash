#!/bin/bash
# Helping script to run fwtrash.py with tcpdump.
# v0.1 - prepared for attack of spoofed ips on http server
#--
# tcpdump ex.:
# tcpdump -r out.cap -nn -s0 port 443 or 80 -W 99 -l
# or use live capturing without option -r
# tcpdump -i enp2s0 -nn -s0 -W99 -l port 443 or 80
#--
