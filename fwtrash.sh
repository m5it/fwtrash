#!/bin/bash

#--------------------------------------------------------------------
#                   logtrash.py by beaykos.69.mu
#                       & wanabe hackers :)
#--------------------------------------------------------------------

#--
#
b=0
s=$(cat badips.out|wc -l)
#
while true; do
    tail -n 50 /var/log/nginx/access.log | ./logtrash.py -o badips.out
    
    n=$(cat badips.out|wc -l)
    
    echo "s vs n: "$s" vs "$n" / "$b
    
    if [[ $((s)) -lt $((n)) ]]; then
        echo "Got new ips to block..."
        s=n
        ./fw.sh
        let b=b+1
    fi
    
    sleep 5
done
