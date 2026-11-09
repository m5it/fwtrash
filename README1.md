                                                                                                                                                     
     # Live-tailing (recommended on the server — like tail -F, handles nginx rotation):                                                                       
     sudo fwtrash run -P rules/http.rules --input /var/log/nginx/access.log --follow --dry-run                                                                
     # add: -o badips.out -O trash.out -c "iptables -A INPUT -s [--IP]/32 -j DROP" etc.                                                                       
                                                                                                                                                              
     # One-shot batch (processes whole file then exits):                                                                                                      
     sudo fwtrash run -P rules/http.rules --input /var/log/nginx/access.log --dry-run                                                                         
     # limit first N lines for testing:                                                                                                                       
     head -1000 /var/log/nginx/access.log | sudo fwtrash run -P rules/http.rules -n -d                                                                        
                                                                                                                                                              
     # Or pipe (v0.6-compatible, unchanged):                                                                                                                  
     sudo tail -F /var/log/nginx/access.log | sudo fwtrash run -P rules/http.rules -n                                                                         
                                                                                                                                                              
     --follow starts at EOF (like tail -f) so it won't replay the current 15.9 M lines; batch --input without --                                              
     follow does. Batch on the full file (3.5 GB) will take a while — add -d to skip stats spam.                                                              
                                                                                                                                                              
     Known: large-file batch still deadlocks on 15 M lines from to_thread + blocking queue.put, and -i truncates                                              
     template fields at --stat-keys limits (e.g. req;60) — you likely want raw log lines in out_trash.txt for                                                 
     fail2ban instead. 
