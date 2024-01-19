#!/usr/bin/python3.8

#--------------------------------------------------------------------
#                   fwtrash.py
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
	#print("modules.vsftp Debug line: {}".format( line ))
	#--
	#
	crc         = ""
	#
	xobj = {
		# variables retrived from nginx/access.log
		"ip"     :"",
		"date"   :"",
		"req"    :"", # CHMOD, DOWNLOAD, UPLOAD, LOGIN, RENAME, DELETE
		"code"   :"",
		"file"   :"",
		"len"    :0,
		"user"   :"",
		
		# variables retrived from auth.log / ssh
		"service":"",    # Ex.: sshd
		"pid"    :"",    # pid of service
		"port"  :"",     # port user connection if included in log
		"preauth":False, #
		#"message":"",    #
		#"tryuser":"",
		#"tryuser1":"",
		
		# variables used for statistics...
		"repeat" :1,
		"hash"   :"",     #crc32b of line
		#"crc_message":"", # message with replaced some values like port, user
		"last_ts":0,
		"blocked":False,
		"bruteforced":False,
	}

	#--
	#
	a = line.split(" ",11)
	#print("DEBUG MODULE line({}): \n".format(len(a)))
	#arr_dump( a )
	#--
	# get pid and proc name=vsftpd
	b = a[4].split("[")
	xobj["service"] = "{}".format(b[0])        # vsftpd
	xobj["code"]    = "{}".format( a[6] )      # OK, FAIL
	xobj["req"]     = "{}".format( a[7][:-1] ) # DOWNLOAD, CHMOD, UPLOAD, LOGIN
	if len(a)>10:
		xobj["file"]    = "{}".format( (a[10][1:]).split('"')[0] )
	if len(a)>11:
		xobj["len"]     = "{}".format( (a[11].split(",")[0]).split(" ")[0] )
	#--
	# Values inserted after generating crc32b/hash so is possible to get unique hash that include ip and part of message
	#------------------------------------------------------------------------------------------
	crc = crc32b( str.encode(json.dumps(xobj)) )                     # retrive crc without date so it can be checked if is repeated
	xobj["hash"] = crc
	#
	xobj["date"]    = "{} {} {}".format( a[0], a[1], a[2] )
	xobj["pid"]     = "{}".format( b[1].split("]")[0] )
	xobj["user"]    = "{}".format( (a[5][:-1])[1:] )
	xobj["ip"]      = "{}".format( (a[9][1:]).split('"')[0] ) #...
	xobj["last_ts"] = strTs2Sec( xobj["date"], "%b %d %H:%M:%S" )  #
	#print("DEBUG IP vsftp: {}\n".format(xobj["ip"]))
	print("DEBUG xobj: \n")
	arr_dump( xobj )
	#
	return xobj
