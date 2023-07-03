#!/usr/bin/python3.8

#--------------------------------------------------------------------
#                   logtrash.py by beaykos.69.mu
#                       & wanabe hackers :)
#                            & dr0gs
# logtrash_ssh module 4  ssh and maybe other services from auth.log
#--------------------------------------------------------------------
# function XObj(...) is used to split line into useful values
#--------------------------------------------------------------------
from fwtrash import crc32b
from fwtrash import strTs2Sec
from fwtrash import arr_dump
from fwtrash import rmatch
from fwtrash import pmatch
import json

#--
#
def XObj( line ):
	line = line.strip()
	#--
	#
	crc         = ""
	#
	tmpdate     = ""
	tmpmessage  = ""
	tmppid      = ""
	tmpport     = ""
	tmptryuser  = ""
	tmptryuser1 = "" # used when attacker try to change user from User1 ) -> ( User2,
	#
	xobj = {
		# variables retrived from nginx/access.log
		"ip"     :"",
		"date"   :"",
		#"req"    :"",
		#"code"   :"",
		#"len"    :"",
		#"ua"     :"",
		"user"   :"",
		
		# variables retrived from auth.log / ssh
		"service":"",    # Ex.: sshd
		"pid"    :"",    # pid of service
		"port"  :"",     # port user connection if included in log
		"preauth":False, #
		"message":"",    #
		"tryuser":"",
		"tryuser1":"",
		
		# variables used for statistics...
		"repeat" :1,
		"hash"   :"",     #crc32b of line
		"crc_message":"", # message with replaced some values like port, user
		"last_ts":0,
		"blocked":False,
		"bruteforced":False,
	}
	
	#--
	#
	#print("XObj line: {}".format(line))
	a = line.split(" ",5)
	#arr_dump( a )
	#--
	#
	#tmpdate         = "{} {} {}".format(a[0], a[1], a[2])
	tmpdate         = "{} {} {}".format(a[0], a[2], a[3])
	#xobj["user"]    = a[3]
	xobj["user"]    = a[4]
	tmpmessage      = a[5]
	
	#
	if rmatch(a[4],".*\[.*"):
		tmp             = a[4].split("[")
		xobj["service"] = tmp[0]
		tmppid          = tmp[1][0:len(tmp[1])-2]
	else:
		xobj["service"] = a[4]
	
	#--
	# retrive IP if included
	a = pmatch(tmpmessage,"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
	if len(a)>0:
		xobj["ip"] = a[0]

	#--
	# check if [preauth]
	if rmatch(tmpmessage,".*\[preauth\]$"):
		xobj["preauth"] = True
	
	#
	#--
	# retrive PORT if included
	a = pmatch(tmpmessage,"port \d+")
	if len(a)>0:
		tmpport = a[0].split(" ")[1]
	#--
	# retrive username that is trying to access
	#
	a = pmatch(tmpmessage,"password for ([a-zA-Z0-9\!\_\-]+)(?=.)")
	if len(a)>0:
		tmptryuser = a[0]
	a = pmatch(tmpmessage,"invalid user ([a-zA-Z0-9\!\_\-]+)(?=.)")
	if len(a)>0:
		tmptryuser = a[0]
	#
	a = pmatch(tmpmessage,"authenticating user ([a-zA-Z0-9\!\_\-]+)(?=.)")
	if len(a)>0:
		tmptryuser = a[0]
	#
	a = pmatch(tmpmessage,"\) \-\> \(([a-zA-Z0-9\!\_\-]+)(?=.)")
	if len(a)>0:
		tmptryuser1 = a[0]
		
	#--
	# generate "crc_message" so our hash is more unique
	tmp = tmpmessage
	if tmpport!="":
		tmp = tmp.replace(tmpport,"[--PORT]")
	if tmptryuser!="":
		tmp = tmp.replace(tmptryuser,"[--TRYUSER]")
	if tmptryuser1!="":
		tmp = tmp.replace(tmptryuser1,"[--TRYUSER1]")
	xobj["crc_message"] = tmp
	
	#--
	# Values inserted after generating crc32b/hash so is possible to get unique hash that include ip and part of message
	#------------------------------------------------------------------------------------------
	crc = crc32b( str.encode(json.dumps(xobj)) )                     # retrive crc without date so it can be checked if is repeated
	
	#
	xobj["date"]     = tmpdate                                        # set date after generating crc
	xobj["message"]  = tmpmessage
	xobj["pid"]      = tmppid
	xobj["port"]     = tmpport
	xobj["tryuser"]  = tmptryuser
	xobj["tryuser1"] = tmptryuser1
	xobj["last_ts"]  = strTs2Sec( tmpdate, "%b %d %H:%M:%S" )         #
	xobj["hash"]     = crc                                            #
	#
	return xobj

