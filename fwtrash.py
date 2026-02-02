#!/usr/bin/python3
#--------------------------------------------------------------------
#                   fwtrash.py :)
#--------------------------------------------------------------------

#--
#
import sys, getopt
#import re
import os
import os.path
import json
import select
#import zlib
import base64
#from datetime import datetime
import time
import signal
import threading
import importlib
from functions import *
#--
#
g_opt_file_allowedips = "allowedips.txt"  # (-a) Define allowed ips so you wont be blocked
g_opt_file_badips   = ""                  # (-o) Can be set file to writeout bad ips
g_opt_file_trash    = ""                  # (-O) Can be set file to writeout trash
g_opt_file_option   = ""                  # (-m) Set file for options/infos that should be memorized. Ex.: last_ts
g_opt_file_rules    = ""                  # (-P) Set file of rules
#
g_opt_comm_onbadip = ""                # (-c) Command that is executed when trash is found and its ip dont exists between g_badips
g_opt_autosave_option = 10             # Autosave options every 10th thread retrived from log
#
g_opt_stat_last_trash = 5              # Stats will display last 5 trashes
g_opt_pure_max        = 100            # Allow max 100 or X lines to be saved in memory
g_opt_stat_last_pure  = 5              # Stats will display last 5 requests that are marked as pure/fine/ok
#
g_opt_stat_disable      = False        # (-d) Disable stats
g_opt_stat_display_keys = ""           # Keys of object that should be displayed in stats. keys should be separated with comma.
                                       # Ex. keys: date,ip,repeat
g_opt_stat_display_temp = ""           # Template for keys how they should be displayed.
                                       # Ex. template: [--DATE] - ([--REPEAT]) [--IP]
g_opt_stop_next_day = False            # (-D) If True stop the program when new day begin.

#
version         = 0.6
die             = False
parser          = None
g_allowedips    = []
g_badips        = []          # array of bad ips
g_rules         = []          # array to load rules on which we search for trashy requests
g_trash         = []          # array of trashy requests
g_pure          = []          # array of pure requests so they can be better monitored in Stats()
g_bruteforce    = [None]*1000 # array of objects. initialized in Main() if (-b) option is used.
g_bruteforce_keys = []        #
                              # key option should be 0-999
                              # Ex.: "key:0,climit:5,tlimit:10;key:1,climit:3,tlimit:3"
g_curday        = datetime.today().strftime('%d') # used to check if new day began with option "g_opt_stop_next_day"=(True)

# retrived from g_opt_file_option aka options
g_option        = {
	"last_ts":0,
}

#
gh_stats              = 0 # handle to stats thread
#
cnts_all              = 0
cnts_allowed          = 0
cnts_trash            = 0
cnts_pure             = 0
cnts_checked_already  = 0
cnts_autosave_option  = 0
#
cnt_autosave_option   = 0

#--
def signal_handler(sig, frame):
	global die, g_opt_file_option, g_option
	#
	sys.stdout.flush()
	print('logtrash=> stopping... g_opt_file_option: ',g_opt_file_option)
	# save options and what should be memorized
	file_write( g_opt_file_option, json.dumps(g_option), True )
	#
	die=True
	#sys.exit()
	Stats()

#--
#
def nothing():
	global g_opt_file_rules

#
def clearline(msg,end='\r'):
    CURSOR_UP_ONE = '\033[K'
    ERASE_LINE = '\x1b[2K'
    sys.stdout.write(CURSOR_UP_ONE)
    sys.stdout.write(ERASE_LINE+'\r')
    print(msg, end=end)

#--
#
def Load_option():
	global g_opt_file_option, g_option
	#--
	#
	if os.path.exists( g_opt_file_option )==False:
		return False;
	
	print("loading options...")
	
	#--
	with open(g_opt_file_option) as f:
		g_option = json.loads( f.read() )
	return True
	

#--
#
def Load_allowedips():
	global g_opt_file_allowedips, g_allowedips
	#--
	#
	if os.path.exists( g_opt_file_allowedips )==False:
		return False;
	#--
	with open(g_opt_file_allowedips) as f:
		for ip in f:
			if arr_index(g_allowedips, ip.strip())==None:
				g_allowedips.append( ip.strip() )
	print("Loaded allowedips {}".format( len(g_allowedips )))
	return True


#--
#
def Load_badips():
	global g_opt_file_badips, g_badips
	#--
	#
	if os.path.exists( g_opt_file_badips )==False:
		return False;
	#--
	with open(g_opt_file_badips) as f:
		for badip in f:
			if arr_index(g_badips, badip.strip())==None:
				g_badips.append( badip.strip() )
	print("Loaded badips {}".format( len(g_badips )))
	return True

#--
#
def Load_rules():
	global g_opt_file_rules, g_rules
	#--
	#
	if os.path.exists( g_opt_file_rules )==False:
		return False;
	#--
	with open(g_opt_file_rules) as f:
		for line in f:
			if rmatch(line,"^\\#.*")==False: # skip commented line with #
				if rmatch(line,".*\\#.*")!=False: # scrap only line if commented somewhere
					g_rules.append( json.loads( pmatch(line,".*(?=\\#)")[0] ) )
				else:
					g_rules.append( json.loads( line ) )
	print("Loaded rules {}".format( len(g_rules )))
	return True


#
# def Manage_rules():
	# global g_opt_file_rules, g_rules
	# #--
	# #
	# if g_opt_file_rules=="":
		# print("ERROR: Required to define file where rules are saved or retrived. Option (-P). For more info use (-h) as help.")
		# sys.exit(1)
	# #--
	# #
	# while True:
		# #
		# compare = []
		# rule = {
			# "key" :"",  # key that is checked for trashes
			# "type":"1", # type of checking. 1=base64 regex, 2=user regex, 3=plain
			# "data":"",
		# }
		# #
		# print("1.) Show rules.")
		# print("2.) Add rule.")
		# print("3.) Edit rule.")
		# print("4.) Delete rule.")
		# print("5.) Exit")
		# #
		# cmd = input("Choose option: ")
		# #
		# if cmd=="1":
			# i=0
			# for rule in g_rules:
				# print("{}.) {}".format(i,rule))
				# i+=1
		# #
		# elif cmd=="2" or cmd=="3":
			# while True:
				# #
				# if cmd=="3":
					# i = input("rule number: ")
					# if len(g_rules)>int(i):
						# rule = g_rules[int(i)]
					# else:
						# print("rule {} dont exists.".format(i))
						# continue
				# # key
				# tmp = input("Enter key to compare{}: ".format( (" ( {} )".format(rule["key"]) if cmd=="3" else "") ))
				# if cmd=="2" and tmp=="":
					# continue
				# elif cmd=="3" and tmp=="":
					# nothing()
				# else:
					# rule["key"] = tmp
				
				# # type
				# print("#--")
				# print("# Types of checking.")
				# print("# 1=base64 regex, 2=user regex, 3=plain comparing")
				# print("# (4-8) length comparing")
				# print("# 4= >     , 5= >=             , 6= <     , 7= <=             , 8==")
				# print("# 4=greater, 5=greater or equal, 6=smaller, 7=smaller or equal, 8=equal")
				# tmp = input("Enter type of comparing{}: ".format( (" ( {} )".format(rule["type"]) if cmd=="3" else " ( {} )".format(rule["type"])) ))
				# if tmp!="":
					# rule["type"] = tmp
				
				# # data
				# tmp = input("Enter data to compare{}: ".format( (" ( {} )".format(rule["data"]) if cmd=="3" else "") ))
				# if tmp=="":
					# nothing()
				# else:
					# rule["data"] = tmp
				
				# # prompt for additional key:value
				# while True:
					# tmp = input("Enter additional key:value or empty to finish: ")
					# if tmp=="" or rmatch(tmp,".*\:.*")==False:
						# break
					# a=tmp.split(":")
					# rule[a[0]] = a[1]
				# #
				# compare.append( rule )
				
				# #
				# tmp = input("Do you wish add another rule to compare with?(yes/no): ")
				# if tmp=="no":
					# break
			
			# # write to rules
			# if cmd=="2": # add rule
				# file_write( g_opt_file_rules, "{}\n".format(json.dumps(compare)), False )
				# g_rules.append( compare )
			# else:        # edit/overwrite rule
				# file_overline( g_opt_file_rules, compare, int(i) )
				# g_rules[int(i)] = compare
		# #
		# elif cmd=="4": # delete
			# i = input("rule number: ")
			# if len(g_rules)>int(i):
				# n_rules = []
				# x=0
				# for rule in g_rules:
					# if x!=int(i):
						# n_rules.append( rule )
					# x+=1
				# #
				# x=0
				# for rule in n_rules:
					# file_write( g_opt_file_rules, "{}\n".format(json.dumps(rule)), True if x==0 else False )
					# x+=1
				# #
				# g_rules = n_rules
			# else:
				# print("rule {} dont exists.".format(i))
				# continue
		# elif cmd=="5" or cmd.lower()=="quit" or cmd.lower()=="exit":
			# break


#--
#
def Load_trash():
	global g_opt_file_trash, g_trash
	#--
	#
	if os.path.exists( g_opt_file_trash )==False:
		return False;
	#--
	with open(g_opt_file_trash) as f:
		for dump in f:
			g_trash.append( json.loads(dump) )
	print("Loaded trash {}".format( len(g_trash )))
	print("")
	return True

#--
# Function Find_trash() will return index of object if crc32b exists
# On failure return None.
#
def Find_trash( crc ):
	global g_trash
	#
	i=0
	#
	for trash in g_trash:
		if trash["hash"] == crc:
			return i
		i += 1
	return None

#--
#
def Check_trash( xobj ):
	global g_rules
	#--
	# Ex. rules in json:
	#----------------------
	# * rule commands: key, type, data, compareWith, bruteforce_count_key
	#-----------------------------------------------------------------------
	# [{"key": "req", "type": "1", "data": "GET /."}]
	# [{"key": "code", "type": "3", "data": "400"}]
	# [{"key": "req", "type": "2", "data": ".*test\\=123\\&aaa.*"}]
	# [{"key": "req", "type": "1", "data": "GET /.", "bruteforce_count_key":"0",}]
	#-- example of comparing of two rules
	# [{"key": "code", "type": "3", "data": "404"},{"key": "ref", "type": "3", "data": "\"-\""}]
	#--
	# [{"key": "req", "type": "1", "data": "GET /."}]
	#
	#print("DEBUG Check_trash() xobj: \n")
	#arr_dump( xobj )
	
	i        = 0  #
	acompare = [None]*len(g_rules)
	#
	for rules in g_rules:
		cntret = 0 # if cntret same with len of rules then comparison succided
		#
		for rule in rules:
			ret = False
			#
			key = rule["key"]  # key to check
			tmp = rule["data"] # data to check
			typ = rule["type"] # type of check
			#
			tmp1 = xobj[key]
			#--
			# Types of checking.
			# 1=base64 regex, 2=user regex, 3=plain comparing
			# (4-8) is used to compare length
			# 4= >     , 5= >=             , 6= <     , 7= <=             , 8==
			# 4=greater, 5=greater or equal, 6=smaller, 7=smaller or equal, 8=equal  
			#
			if typ=="3" or typ=="2":
				nothing()
			elif typ=="1":
				#
				tmp  = str(base64.b64encode(bytes(tmp, 'utf-8')),'ascii')
				tmp1 = str(base64.b64encode(bytes(tmp1, 'utf-8')),'ascii')
				#
				if rmatch(tmp,"\\=\\=$"): # fix for bug on short rules
					tmp = tmp[:-3] # remove end of base64 so is possible to match anything after
			
			#print("DEBUG Check_trash() debug rule and req: {}={} vs {}={}".format( len(tmp1), tmp1, len(tmp), tmp))
			
			#--
			# String comparisons
			if tmp=="":
				if xobj[key]=="":
					ret = True
			#
			elif (typ=="1" or typ=="2") and rmatch(tmp1,"{}".format( tmp )) != False:
				ret = True
			#
			elif typ=="3" and tmp1==tmp:
				ret = True
			# Length comparisons
			elif typ=="4" and len(tmp1)>int(tmp):
				ret = True
			elif typ=="5" and len(tmp1)>=int(tmp):
				ret = True
			elif typ=="6" and len(tmp1)<int(tmp):
				ret = True
			elif typ=="7" and len(tmp1)<=int(tmp):
				ret = True
			elif typ=="8" and len(tmp1)==int(tmp):
				ret = True
			#--
			# Commands defined with rule
			# * commands as rule keys:
			#   (Bruteforce multiple/single rule check):
			#   - bruteforce_count_key = 0 # Set key/number under which rules can count/reset counts of brutefore actions.
			#   To set count & time limit for bruteforce_count_key use command line argument (-b)
			#     used strings as options: - key      # For this key these options will be used
			#                              - climit   # Count limit. If this is reached action is fired.
			#                              - tlimit   # Time limit. If count is reached in this time or before action is fired.
			#   Ex.: -b "key:0,climit:5,tlimit:10;key:1,climit:3,tlimit:3"
			#
			if "bruteforce_count_key" in rule:
				xobj["bruteforce_count_key"] = rule["bruteforce_count_key"]
			#
			if ret==True:
				cntret+=1
		
		#
		#if ret==True:
		if cntret==len(rules):
			return {"xobj":xobj,"isTrash":True,}
		i+=1
	return {"xobj":xobj,"isTrash":False,}

#--
# function Parse( line )...
# Real parsing of line happen in defined module (-p). Ex.: logtrash_http aka logtrash_http.py and function XObj(...)...
#
def Parse( line ):
	global g_allowedips, g_bruteforce, g_bruteforce_keys, parser, g_trash, g_badips, cnts_allowed, cnts_checked_already, cnts_autosave_option, cnts_all, cnts_pure, cnts_trash, g_opt_file_badips, g_opt_file_trash, g_opt_comm_onbadip, cnt_autosave_option, g_opt_autosave_option, g_opt_file_option, g_option, g_opt_pure_max, g_pure
	
	#--
	# function XObj(...)
	# retrived variables:
	# x_ip, x_date, x_req, x_code, x_len, x_ua
	# x_date can be formated
	# x_req  can be splited and used
	#
	#print("DEBUG Parsing line: {}".format(line))
	try:
		xobj = parser.XObj( line )
		print("Parse() xobj: ")
		print(xobj)
	except Exception as E:
		print("Parse() ERROR: ",E)
		print("Line: ",line)
		return False
	#
	if xobj is None:
		print("Parse() Failed line ",line)
		return False
	#crc  = xobj["crc"]
	crc = xobj["hash"]
	#arr_dump(xobj)
	#--
	# check if line is trash/attacker/..:)
	tmp  = Check_trash( xobj )
	print("Check_trash({}): {}".format( crc, tmp ))
	#
	xobj = tmp["xobj"]
	
	#--
	# Check if thread was already checked if so skip/continue...
	# if g_option["last_ts"]>0 and g_option["last_ts"]>=xobj["last_ts"]:
		# cnts_checked_already+=1
		# print("Parse( {} ) Thread already checked! xobjTS: {} optTS: {} = {}/s".format( crc, xobj['last_ts'], g_option['last_ts'], (g_option["last_ts"]-xobj["last_ts"]) ))
		# return False
	# else:
		# print("Parse( {} ) Checking first time!".format( crc ))
	
	#--
	# Check if is allowed ip then skip.
	#if xobj["ip"] != "" and arr_index(g_badips,xobj["ip"]) == None:
	if xobj["ip"] != "" and arr_index(g_allowedips,xobj["ip"]) != None:
		#print("Allowed ip {}, skipping...".format( xobj["ip"] ))
		cnts_allowed+=1
	#--
	#
	elif tmp["isTrash"]:
		#--
		#
		blocked            = False
		bruteforced        = False
		bruteforce_enabled = False
		
		#--
		# Check if bruteforce_count_key is set if so increase count and compare with time & count limit. if count is reached in specific time if set
		#   badip action is fired.
		if len(g_bruteforce_keys) and "bruteforce_count_key" in xobj:
			print("DEBUG bruteforce_count_key ",xobj["bruteforce_count_key"])
			#
			bruteforce_enabled = True
			#
			c = g_bruteforce[int(xobj["bruteforce_count_key"])]
			print("DEBUG bruteforce_count_key c",c)
			print("DEBUG g_bruteforce: ",g_bruteforce)
			#
			c["count"] += 1
			c["timelast"] = int( time.time() )
			#
			if c["timefirst"]==0:
				c["timefirst"] = int(time.time())
			# check if bruteforced
			if (c["count"] >= c["climit"]):
				if c["tlimit"]==None:
					bruteforced = True
				elif ( (c["timelast"]-c["timefirst"])<=c["tlimit"] ):
					bruteforced = True
			# clear counts to check bruteforce
			if bruteforced:
				c["count"]     = 0
				c["timefirst"] = 0
				c["timelast"]  = 0
			elif (c["count"] >= c["climit"] and c["tlimit"]==None) or ( (c["timelast"]-c["timefirst"])>=c["tlimit"] ):
				c["count"]     = 1
				c["timefirst"] = int(time.time())
				c["timelast"]  = int(time.time())
			#
			if bruteforced:
				c["reached"]+=1
			g_bruteforce[int(xobj["bruteforce_count_key"])] = c
		
		#--
		# check if bad ip exists
		# xobj["ip"] can be empty when running logtrash on auth.log to observe ssh service
		if (xobj["ip"] != "" and arr_index(g_badips,xobj["ip"]) == None and bruteforce_enabled==False) or (xobj["ip"] != "" and arr_index(g_badips,xobj["ip"]) == None and bruteforce_enabled==True and bruteforced):
			#
			g_badips.append( xobj["ip"] )
			#
			blocked = True
			#--
			# Write not existing bad ip into specific file
			#
			if g_opt_file_badips!="":
				file_write( g_opt_file_badips, "{}\n".format(xobj["ip"]) )
			#--
			# Exec command on not existing bad ip
			#
			if g_opt_comm_onbadip!="":
				cmd = g_opt_comm_onbadip.replace("[--IP]",xobj["ip"])
				os.system(cmd)
		
		#--
		# check if trash already exists in g_trash
		i = Find_trash( crc )
		print("Find_trash( {} ): {}".format( crc, i ))
		#
		if i is not None: # trash exists
			#
			xobj = g_trash[i]
			#
			xobj["blocked"]     = blocked
			xobj["bruteforced"] = bruteforced
			xobj["repeat"]      +=1
			#g_trash[i] = xobj
			g_trash.pop(i)
			g_trash.append(xobj)
			#
			if g_opt_file_trash!="":
				#file_overline( g_opt_file_trash, xobj, i )
				file_write(g_opt_file_trash, "{}\n".format( json.dumps(xobj) ), True)
		else:             # trash dont exists
			#
			xobj["blocked"]     = blocked
			xobj["bruteforced"] = bruteforced
			#
			g_trash.append( xobj )
			#
			if g_opt_file_trash!="":
				file_write( g_opt_file_trash, "{}\n".format( json.dumps(xobj) ) )
		#
		cnts_trash += 1
	else:
		#--
		# save pure requests in "g_pure" so they can be displayed in stats or maybe something more in future..
		# limit of g_pure array is defined with g_opt_pure_max. When limit is achieved one is removed/poped and new is appended to end.
		#
		if len(g_pure)>=g_opt_pure_max:
			dumping = g_pure.pop(0)
		#
		g_pure.append(xobj)
		#
		cnts_pure += 1
	cnts_all+=1
	
	#--
	# Save last timestamp that was checked
	#if "last_ts" in g_option:
	g_option["last_ts"] = xobj["last_ts"]
	#--
	#
	if cnt_autosave_option>=g_opt_autosave_option:
		# save options and what should be memorized
		file_write( g_opt_file_option, json.dumps(g_option), True )
		cnt_autosave_option=0
		cnts_autosave_option+=1
	else:
		#
		cnt_autosave_option+=1
	return True

#--
#
def Help():
	global version
	#--
	#
	print("logtrash.py v{} options: ".format(version))
	print("--------------------")
	print("-h - Help for logtrash.")
	print("-v - Display logtrash version.")
	#print("-A - Append rule to logtrash db.")
	print("-m - Set filename for options.")
	print("-P - Set filename for rules.")
	print("-o - Set filename where bad ips should be writed.")
	print("-O - Set filename where trash should be writed.")
	print("-c - Set command that is executed when bad ip is found. Support argument \"[--IP]\" which is replaced for badip address.")
	print("-p - Set parser (default: \"logtrash_http\" for /var/log/nginx/access.log)")
	print("-s - Define keys that are used to display statistics. Ex. (req is limited to 60chars): date,ip,repeat,req;60,ref;30,ua;30,code,len")
	print("-S - Set template for defined keys for statistic. Ex.: -S \"[--DATE] - ([--REPEAT],[--CODE],[--LEN]) [--IP] => [--REQ]\"")
	print("-b - Set options for bruteforce checking. Ex.: -b key:0,climit:3,tlimit:6")
	print("")
	print("Usage: tail -f /var/log/nginx/access.log | ./logtrash.py")
	print("       tail -f /var/log/nginx/access.log | ./logtrash.py -o badips.out -O trash.out")
	print("       tail -f /var/log/nginx/access.log | ./logtrash.py -o badips.out -c \"iptables -A INPUT -s [--IP] -j DROP\"")
	print("       tail -f /var/log/nginx/access.log | ./logtrash.py > stats.out&")
	print("       tail -f /var/log/nginx/access.log | ./logtrash.py -P p3.txt -o badips.out -O trash.out -s \"date,ip,repeat,req;60,ref;30,ua;30,code,len\" -S \"[--DATE] - ([--REPEAT],[--CODE],[--LEN]) [--IP] => [--REQ] ua: [--UA], ref: [--REF]\" -p logtrash_http -b \"key:0,climit:3,tlimit:10\"")
	print("       ./logtrash.py -A \"GET /portal/redlion HTTP/1.1\"")
	print("")
	print("Tips:  tail can be replaced for cat :)")
	print("")

#--
# generate stat line from defined keys and template
def StatsTemp(xobj):
	global g_opt_stat_display_keys, g_opt_stat_display_temp
	akeys = g_opt_stat_display_keys.split(",")
	ret   = g_opt_stat_display_temp
	cnt   = 0
	for k in akeys:
		key   = akeys[cnt]
		limit = None
		data  = ""
		# check if key contain limit argument then limit/substr text
		# key ex.: req;70
		#
		if rmatch(key,".*\\;.*"):
			a     = key.split(";")
			key   = a[0]
			limit = int(a[1])
		
		#
		if key in xobj:
			data = xobj[key]
			#
			if limit != None and len(data)>limit:
				data = data[0:limit]
			# generate stat line
			ret = ret.replace( "[--{}]".format(key.upper()), "{}".format(data) )
		else:
			# key dont exists. just replace format with empty
			ret = ret.replace( "[--{}]".format(key.upper()), "" )
		cnt+=1
	return ret

#--
# function Stats() used to display stats and maybe some other functionality like for option g_opt_stop_next_day
# Function is running as thread in loop with timeout 1s.
#
def Stats():
	global g_curday, g_opt_stop_next_day, g_rules,g_bruteforce, g_bruteforce_keys, die,cnts_allowed, cnts_all, cnts_pure, cnts_trash, g_trash, g_pure, g_badips, g_opt_stat_last_trash, g_opt_stat_last_pure
	
	cnt             = 0
	last_load_check = int(time.time()) # to check when badips was loaded last time. used if program is running with multiple modules and ips are synchronized
	#--
	#
	print("")
	#
	while die==False:
		sys.stdout.flush()
		
		#--
		# functionality for option g_opt_stop_next_day
		# Stop the program if new day began. Useful to run in bash loop to rerun logtrash.py
		clearline("Debug g_curday: {} vs. now: {}".format(g_curday,datetime.today().strftime('%d')))
		if g_curday!=datetime.today().strftime('%d'):
			print("LogTrash => Exiting cause of -D option and next day...")
			die=True
			sys.exit()
			
		#--
		# display statistics in loop
		clearline("LogTrash => Uptime {}/s".format(cnt),'\n')
		clearline("All            : {}".format(cnts_all),'\n')
		clearline("Allowed        : {}".format(cnts_allowed),'\n')
		clearline("Pure           : {}".format(cnts_pure),'\n')
		clearline("Trash          : {}".format(cnts_trash),'\n')
		#clearline("Rules          : {}".format(len(g_rules)),'\n')
		clearline("Checked already: {}".format(cnts_checked_already),'\n')
		clearline("Autosave option: {}".format(cnts_autosave_option),'\n')
		clearline("Badips         : {}".format( len(g_badips) ),'\n')
		if len(g_badips)>0:
			clearline("Last badip     : {}".format( g_badips[len(g_badips)-1] ),'\n')
		clearline("All trash      : {}".format( len(g_trash) ),'\n')
		
		#--
		# display last X trashes
		cntx=0
		if len(g_trash)>0:
			clearline("Last {} trashes: ".format(g_opt_stat_last_trash),'\n')
		for x in reversed(range( -1, len(g_trash)-1 )):
			#
			if cntx>=g_opt_stat_last_trash:
				break
			#
			o  = g_trash[x]
			#
			clearline("{}.) {}".format((x+1),StatsTemp(o)),'\n')
			cntx+=1
		
		#--
		# display last X pure log lines
		cntx=0
		if len(g_pure)>0:
			clearline("Last {} pure: ".format(g_opt_stat_last_pure),'\n')
		for x in reversed(range( -1, len(g_pure)-1 )):
			#
			if cntx>=g_opt_stat_last_pure: # break when reach limit
				break
			#
			o  = g_pure[x]
			#
			clearline("{}.) {}".format((x+1),StatsTemp(o)),'\n')
			cntx+=1
		
		#--
		# display bruteforce stats
		for i in g_bruteforce_keys:
			o = g_bruteforce[i]
			# reset count if timelimit pased
			if o["tlimit"]!=None and o["timefirst"]>0 and ( (int(time.time())-o["timefirst"])>=o["tlimit"] ):
				o["count"]      = 0
				o["timefirst"]  = 0
				o["timelast"]   = 0
				g_bruteforce[i] = o
			#
			clearline("bruteforce key: {} reached: {} - {}/{} {}->{}/{}".format( i,o["reached"],o["count"],o["climit"],o["timefirst"], o["timelast"], o["tlimit"] ),'\n')
		
		#-- CLEAN TERMINAL AND LINES OF STATISTICS
		# jump back to overwrite/clear lines of statistics
		# cleaning of lines should work with \x1b[1K
		time.sleep(1)

		sys.stdout.write('\x1b[1A') #-- go up line | LogTrash
		sys.stdout.write('\x1b[1A') #-- go up line | All
		sys.stdout.write('\x1b[1A') #-- go up line | Allowed
		sys.stdout.write('\x1b[1A') #-- go up line | Pure
		sys.stdout.write('\x1b[1A') #-- go up line | Trash
		sys.stdout.write('\x1b[1A') #-- go up line | Checked already
		sys.stdout.write('\x1b[1A') #-- go up line | Autosave option
		sys.stdout.write('\x1b[1A') #-- go up line | Badips
		sys.stdout.write('\x1b[1A') #-- go up line | All trash
		
		sys.stdout.write('\x1b[1A') #-- go up line | DEBUG one line
		
		#--
		# jump back for number of displayed last trashes
		cntx=0
		for x in reversed(range( -1, len(g_trash)-1 )):
			if cntx>=g_opt_stat_last_trash:
				break
			sys.stdout.write('\x1b[1A') #-- go up line
			cntx+=1
		if len(g_trash)>0:
			sys.stdout.write('\x1b[1A') #-- go up line 4 Last X trashes
		
		#--
		# jump back for number of displayed last pure
		cntx=0
		for x in reversed(range( -1, len(g_pure)-1 )):
			if cntx>=g_opt_stat_last_pure:
				break
			sys.stdout.write('\x1b[1A') #-- go up line
			cntx+=1
		if len(g_pure)>0:
			sys.stdout.write('\x1b[1A') #-- go up line 4 Last X pure
		
		#--
		# bruteforce stats
		for i in g_bruteforce_keys:
			sys.stdout.write('\x1b[1A')
		#--
		if len(g_badips)>0:
			sys.stdout.write('\x1b[1A') #-- go up line
		
		#--
		# load/check for badips if there are any new. bad ips can be retrived with other module and like that they are synchronized.
		# (idea: maybe this we should connect programs trough server like ircbot..)
		if ( int(time.time()) - last_load_check ) >= 360:
			Load_badips()
			last_load_check = int(time.time())
		
		#
		if cnt==5:
			os.system("clear")
			print("Screen cleared.")
			time.sleep(3)
		#
		cnt+=1

#--
#
def main(argv):
	global g_opt_file_allowedips, g_opt_stop_next_day, g_bruteforce, g_bruteforce_keys, g_opt_stat_display_keys, g_opt_stat_display_temp, g_opt_file_rules, g_opt_file_badips, g_opt_file_trash, g_opt_comm_onbadip, gh_stats, gh_commands, version, parser, g_opt_import_parser, g_opt_file_option,g_badips,g_opt_stat_disable
	
	#--
	opts           = []
	opt_help       = False
	opt_append     = False
	opt_parser     = "modules.logtrash_http" # default parser for nginx and /var/log/nginx/access.log
	opt_bruteforce = ""                      # Ex.: "key:0,climit:5,tlimit:10;key:1,climit:3,tlimit:3"
	
	#--
	try:
		opts, args = getopt.getopt(argv,"vhP:Aa:o:O:c:p:s:S:b:m:Dd",[])
	except getopt.GetoptError:
		opt_help = True
	
	#--
	#
	for opt, arg in opts:
		if opt=="-h":
			opt_help = True
		elif opt=="-v":
			print("logtrash version {}".format(version))
			sys.exit()
		elif opt=="-A":
			opt_append = True
		elif opt=="-P":
			g_opt_file_rules = arg
		elif opt=="-m":
			g_opt_file_option = arg
		elif opt=="-o":
			g_opt_file_badips = arg
		elif opt=="-a":
			g_opt_file_allowedips = arg
		elif opt=="-O":
			g_opt_file_trash = arg
		elif opt=="-c":
			g_opt_comm_onbadip = arg
		elif opt=="-p":
			opt_parser = arg
		elif opt=="-d":
			g_opt_stat_disable = True
		elif opt=="-s":
			g_opt_stat_display_keys = arg
		elif opt=="-S":
			g_opt_stat_display_temp = arg
		elif opt=="-b":
			opt_bruteforce = arg
		elif opt=="-D":
			g_opt_stop_next_day = True
	
	#--
	if g_opt_file_option=="":
		g_opt_file_option = "{}.opts".format(opt_parser)
	# print("DEBUG g_opt_file_option: ",g_opt_file_option)
	# #exit(1)
	# #
	# print("")
	# print("---------------------------------------------------------------")
	# print("             --=[ LogTrash by beaykos.69.mu ]=--               ")
	# print("---------------------------------------------------------------")
	# print("          LogTrash will help keeping you trash away            ")
	# print("---------------------------------------------------------------")
	# print("                          version {}                           ".format(version))
	# print("")
	
	# #
	# #print("opt_append             :     (-A): {}".format(opt_append))
	# print("opt_parser             :     (-p): {}".format(opt_parser))
	# print("opt_bruteforce         :     (-b): {}".format(opt_bruteforce))
	# print("g_opt_file_option      :     (-m): {}".format(g_opt_file_option))
	# print("g_opt_file_rules       :     (-P): {}".format(g_opt_file_rules))
	# print("g_opt_file_allowedips  :     (-a): {}".format(g_opt_file_allowedips))
	# print("g_opt_file_badips      :     (-o): {}".format(g_opt_file_badips))
	# print("g_opt_file_trash       :     (-O): {}".format(g_opt_file_trash))
	# print("g_opt_comm_onbadip     :     (-c): {}".format(g_opt_comm_onbadip))
	# print("g_opt_stat_disable     :     (-d): {}".format(g_opt_stat_disable))
	# print("g_opt_stat_display_keys:     (-s): {}".format(g_opt_stat_display_keys))
	# print("g_opt_stat_display_temp:     (-S): {}".format(g_opt_stat_display_temp))
	# print("g_opt_stop_next_day    :     (-D): {}".format(g_opt_stop_next_day))
	# print("")
	
	#--
	#
	Load_option()
	Load_allowedips()
	Load_badips()
	Load_rules()
	Load_trash()
	#--
	signal.signal(signal.SIGINT, signal_handler)
	#--
	# DEBUG ONLY
	#print("DEBUG g_badips: \n")
	#arr_dump( g_badips )
	#print("DEBUG g_allowedips: \n")
	#arr_dump( g_allowedips )
	
	#--
	if   opt_help:
		Help()
		sys.exit(1)
	elif opt_append==True:
		#Manage_rules()
		Help()
		sys.exit(1)
	elif opt_bruteforce!="":
		a=opt_bruteforce.split(";")
		for tmp in a:
			#
			key = 0               # (0-999) - Key where to count and what rules are included there by "bruteforce_count_key".
			o = {
				"count"    :0,       #
				"timefirst":0,       #
				"timelast" :0,       #
				"reached"  :0,       # Number of times count was reached
				"climit"   :None,    # (set from command prompt arg (-b)) count limit
				"tlimit"   :None,    # (set from command prompt arg (-b)) time limit
			}
			#
			b = tmp.split(",")
			for tmp1 in b:
				c = tmp1.split(":")
				if c[0]=="key":
					key = int(c[1])
				else:
					o[c[0]] = int(c[1])
			#
			if o["climit"]==None:    # Skip settings if climit is not set
				continue
			#
			g_bruteforce[key] = o
			g_bruteforce_keys.append( key )
	#print("DEBUG g_bruteforce_keys( {} ): {}".format( len(g_bruteforce_keys), g_bruteforce_keys))
	#exit(1)
	#--
	#if select.select([sys.stdin,],[],[],0.0)[0]:
	#	nothing()
	#else:
	#	Help()
	#	sys.exit(1)
	
	#--
	#
	#from logtrash_http import XObj
	#import logtrash_http as parser
	try:
		parser = importlib.import_module( opt_parser )
	except Exception as E:
		print("logtrash: Failed to load parser {}, {}".format( opt_parser, E ))
		sys.exit()
	
	#--
	# thread for displaying of stats
	if g_opt_stat_disable==False:
		gh_stats = threading.Thread(target=Stats,args=( ))
		gh_stats.start()
	
	#--
	#
	for line in sys.stdin:
		Parse( line )

#--
if __name__ == '__main__':
	#--
	main(sys.argv[1:])
