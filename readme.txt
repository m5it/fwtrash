#--------------------------------------------------------------------
#                   FWTrash by grandekos.com
#--------------------------------------------------------------------
# Last update: 
# 8.7.23
#-----------------
# With wrong rules you can block even your self!
#--------------------------------------------------------------------


Contain files:
--------------
  - runwhile_http.sh  (simple START for nginx)
  - runwhile_ssh.sh   (simple START for ssh)
  - fwtrash.py        (script that do the work)
  - modules/http.py   (used optionaly)
  - modules/ssh.py    (used optionaly)
  - rules/http.rules  (used optionaly)
  - rules/ssh.rules   (used optionaly)
  - run_http.sh       (used with runwhile_http.sh)
  - run_ssh.sh        (used with runwhile_ssh.sh)
  - fw.sh             ( iptables script that was used in v0.1 maybe in future can be included again )
  - other files created by script or just trash...

Contain modules:
----------------
  - modules/http.py
  - modules/ssh.py
  
Contain rules:
--------------
  - rules/http.rules
  - rules/ssh.rules



#--
# Some examples of usage:

# (8.7.23)
# Use of files: runwhile_http.sh OR runwhile_ssh.sh (Just simplify steps..)
# Ex.:
nohup ./runwhile_http.sh&
# OR
nohup ./runwhile_ssh.sh&

# Ex. preview of outputs:
tail -f run_http.out
# OR
tail -f run_ssh.out

#-- Examples with arguments and options from run_http.sh, run_ssh.sh
# 1.) Example with module "http".
tail -f /var/log/nginx/access.log | ./fwtrash.py -P rules/http.rules -o badips.out -O trash_http.out -p modules.http -s "date,ip,repeat,req;60,ref;20,ua;20,code,len" -S "[--DATE] - ([--REPEAT],[--CODE],[--LEN]) [--IP] => [--REQ] ua: [--UA], ref: [--REF]" -c "iptables -A INPUT -s [--IP]/32 -j DROP" -b "key:1,climit:3,tlimit:5;key:2,climit:3,tlimit:6"

# 2.) Example module "ssh"
tail -f /var/log/auth.log | ./fwtrash.py -o badips.out -O trash_ssh.out -P rules/ssh.rules -p modules.ssh -s "date,ip,repeat,message;100" -S "[--DATE] [--IP]([--REPEAT]) => [--MESSAGE]" -c "iptables -A INPUT -s [--IP]/32 -j DROP" -b "key:0,climit:3,tlimit:60;key:1,climit:3,tlimit:120"


To get more help write "./fwtrash.py -h"



#------------------------------------
# How is useful, used or how it works:
#------------------------------------
Can be used to block bad ips, ips that send suspicious requests.
Can be used to analyze requests or generating statistics.
Can be used with any program that send data to stdout or trough bash pipes.

How it works is that you should load multiple rules on which program recognize bad requests, bad lines of data.

Modules are used to parse/split line of data into values which are compared with rules if they have such configuration.
Rules are writed in JSON. Each line is json array that can contain multiple objects. Object should contain specific keys:values.

Default keys for rules:
  - key    # KEY => can be used depend on module you are using. For ex. for module "logtrash_http" keys: 
           #        ip, date, req, code, len, ref, ua, repeat, hash, last_ts.
           #        If you open with text editor file: modules/logtrash_http.py you will find keys that can be used within rules.
  - type   # TYPE => is used to define what kind of comparing you wish to use when searching for bad data.
           #         1: base64+regex, 2: regex, 3: plain compare, 4-8 are length comparing. 4:>=, 5:>, 6:<=, 7:<, 8:==
  - data   # DATA => is used to set string that will be compared with value of specific key inside of object.
Additional keys:
  - bruteforce_count_key # is number 1-999 and is used to set additional options for specific rule.
                         # Options: key, climit & tlimit. tlimit is optional and is used to specify time in seconds.
                         # Ex.: -b "key:1,climit:3,tlimit:5;key:2,climit:5"

Default keys for modules:
  - date
  - ip           ( Can be empty. Depent on rule what can capture. )
  - repeat       ( Integer. Number of times trash repeated. )
  - blocked      ( True | False )
  - bruteforced  ( True | False )
  - hash         ( crc32b )
  - last_ts      ( timestamp in sec )
Other keys can be found by viewing modules/logtrash_http.py or modules/logtrash_ssh.py and check what keys xobj object contain.


#---------------
# About versions:
#---------------


#--------------------------------------------------------------------
*  version 0.5
Added clearing of bruteforce stats into thread Stats() that run in loop and sleep 1/s so is perfect for clearing.
Added option to stop the program when new day begin. Useful because system logs create new file so
 running of program is no more useful if is not restarted with new log..

#--------------------------------------------------------------------
* 19.10.21 version 0.4
Moved modules and rules as submodules of fwtrash.git repository.
Updates of readme..:)

#--------------------------------------------------------------------
* 18.10.21 version 0.3
Separated parsing of data by creating modules.
Updated syntax of rules. Line is array that can contain multiple objects. Object is rule constructed with keys&values. 
  If there is more objects in array they get compared between each other. If all are succesfuly compared line of data is marked as bad line..
Added bruteforce detection. 

#--------------------------------------------------------------------
* 11.10.21 version 0.2
Updated display of statistics by flushing and overwriting to stdout.
Added option to execute a command when new bad ip is found.
Updated usage with linux pipes ex.: 
tail -f /var/log/nginx/access.log | ./logtrash.py -o badips.out -O trash.out -c "iptables -A INPUT -s [--RIP -J DROP]" > stats.out&
tail -f stats.out # to run program in background and just tailing the statistics.

#--------------------------------------------------------------------
* x.10.21 version 0.1
This version is useful to run in bash loop like that script is monitoring all the time trafic to server.
To run FWTrash in bash loop is created script "fwtrash.sh".

Other usage is trough linux pipes and commands like "cat" or "tail".
Ex.: cat /var/log/nginx/access.log | ./logtrash.py -o badips.out







Happy hunting...
