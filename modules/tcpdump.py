#!/usr/bin/python3.8

#--------------------------------------------------------------------
#                   fwtrash.py
#            http.py 4 NGINX and maybe APACHE
#--------------------------------------------------------------------
# function XObj(...) is used to split line into useful values
#--------------------------------------------------------------------
from functions import crc32b
from functions import strTs2Sec
import json, re

#
def XObj( line ):
	#line_check = line.split(" ")
	#if len(line_check)<=3:
	#print("http.py => XObj Failed line, skipping( {} ): {}".format( len(line_check), line ))
	#return None
	#print("http.py => XObj line( {} ): {}".format( len(line_check),line ))
	#--
	tmpdate = None
	# returned object
	xobj = {
		# variables retrived from log
		"ip"     :"",
		"date"   :"",
		"req"    :"",
		"code"   :"",
		"len"    :"",
		"ref"    :"",
		"ua"     :"",
		# variables from error
		"host"    :"",
		"upstream":"",
		"server"  :"",
		"data"    :"",
		# variables added by program
		"repeat" :1,
		"hash"   :"", #crc32b of line
		"last_ts":0,
		"blocked":False,
		"count":0,
		"bruteforced":False,
	}
	#--
	#
	a = line.split(" ",11)
	print("tcpdump.py => a: ",a)
	
	#
	crc = crc32b( str.encode(json.dumps(xobj)) ) # retrive crc without date so it can be checked if is repeated
	#print("DEBUG tmpdate: ",tmpdate)
	#
	xobj["date"]    = tmpdate                    # set date after generating crc
	if tmpdate != None:
		xobj["last_ts"] = strTs2Sec(tmpdate)     #
	xobj["hash"]    = crc                        #
	#
	return xobj
