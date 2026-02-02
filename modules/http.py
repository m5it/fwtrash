#!/usr/bin/python3.8

#--------------------------------------------------------------------
#                   fwtrash.py
#            http.py 4 NGINX and maybe APACHE
#--------------------------------------------------------------------
# function XObj(...) is used to split line into useful values
#--------------------------------------------------------------------
from fwtrash import crc32b
from fwtrash import strTs2Sec
import json

#--
#
def XObj( line ):
	line_check = line.split(" ")
	if len(line_check)<=3:
		print("http.py => XObj Failed line, skipping( {} ): {}".format( len(line_check), line ))
		return None
	print("http.py => XObj line( {} ): {}".format( len(line_check),line ))
	#--
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
		# variables added by program
		"repeat" :1,
		"hash"   :"", #crc32b of line
		"last_ts":0,
		"blocked":False,
		"count":0,
		"bruteforced":False,
	}
	
	# line ex.:
	# 209.141.56.212 - - [06/Oct/2021:12:42:26 +0100] "GET /config/getuser?index=0 HTTP/1.1" 404 118 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0"
	# short ex.:
	# ip - - [date] "request" HTTPCODE LEN "-" "useragent"

	#--
	#
	a = line.split(" ",3)
	
	#--
	# Split line of log. Some values are skipped. They can be used in future.
	#
	xobj["ip"]   = a[0]
	tmp          = a[3]
	print("XObj D1",a)
	a            = tmp.split("] ",1)
	print("XObj D2",a)
	tmpdate      = a[0][1:len(a[0])]
	tmp          = a[1]
	a            = tmp.split("\"",2)
	xobj["req"]  = a[1]
	tmp          = a[2]
	a            = tmp.split(" ",4)
	xobj["code"] = a[1]
	xobj["len"]  = a[2]
	xobj["ref"]  = a[3]
	tmp          = a[4]
	a            = tmp.split("\"",2)
	xobj["ua"]   = a[1]
	
	#--
	#
	crc = crc32b( str.encode(json.dumps(xobj)) ) # retrive crc without date so it can be checked if is repeated
	#
	xobj["date"]    = tmpdate                    # set date after generating crc
	xobj["last_ts"] = strTs2Sec(tmpdate)         #
	xobj["hash"]    = crc                        #
	#
	return xobj
