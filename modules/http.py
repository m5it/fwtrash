#!/usr/bin/python3.8

#--------------------------------------------------------------------
#                   fwtrash.py
#            http.py 4 NGINX and maybe APACHE
#--------------------------------------------------------------------
# function XObj(...) is used to split line into useful values
#--------------------------------------------------------------------
from fwtrash import crc32b
from fwtrash import strTs2Sec
import json, re

#--
# Ex.:
# tmp = fix_datetime('2026/01/31 03:32:38')
def fix_datetime(input_str):
	# Split the input string into date and time parts
	date_str, time_str = input_str.split()

	# Split the date into year, month, and day
	year, month, day = date_str.split('/')

	# Define a dictionary to map numeric month to its abbreviation
	month_abbr = {
		'01': 'Jan',
		'02': 'Feb',
		'03': 'Mar',
		'04': 'Apr',
		'05': 'May',
		'06': 'Jun',
		'07': 'Jul',
		'08': 'Aug',
		'09': 'Sep',
		'10': 'Oct',
		'11': 'Nov',
		'12': 'Dec'
	}

	# Get the month abbreviation
	month_abbr = month_abbr[month]

	# Format the final output
	formatted_date = f"{day}/{month_abbr}/{year}"
	result = f"[{formatted_date}:{time_str} +0000]"

	return result

#-- tmpobj = extract_log_fields(log_line)
# input: 
# 28076#28076: *64310 FastCGI sent in stderr: "Primary script unknown" while reading response header from upstream, client: 8.222.225.103, server: aiia.grandekos.com, request: "GET /public/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1", upstream: "fastcgi://unix:/run/php8.2-fpm.sock:", host: "2.139.221.31:443"\n

# output: 
# {'client': '8.222.225.103,', 'server': 'aiia.grandekos.com,', 'request': 'GET /public/vendor.... HTTP/1.1', 'upstream': 'fastcgi://unix:/run/...:', 'host': '2.139.221.33'}
def extract_log_fields(log_line):
	# Match the key-value pairs using regex
	pattern = r"""
		(client|server):\s*(\S+)                # Unquoted values for client/server
		| 
		(request|upstream|host):\s*"(.*?)"       # Quoted values for request/upstream/host
	"""
	matches = re.findall(pattern, log_line, re.VERBOSE)
	
	result = {}
	for match in matches:
		if match[0]:  # client or server
			result[match[0]] = match[1]
		else:         # request, upstream, or host
			result[match[2]] = match[3]
	
	return result

#
def XObj( line ):
	line_check = line.split(" ")
	if len(line_check)<=3:
		#print("http.py => XObj Failed line, skipping( {} ): {}".format( len(line_check), line ))
		return None
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
		"host"   :"",
		"upstream":"",
		"server":"",
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
	# Debug ok line:
	# http.py => XObj line( 20 ): 185.12.59.118 - - [02/Feb/2026:09:14:32 +0000] "GET / HTTP/1.1" 400 255 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
	# Debug fail line (error):
	# ttp.py => XObj line( 30 ): 2026/02/02 07:44:47 [error] 28076#28076: *74161 FastCGI sent in stderr: "Primary script unknown" while reading response header from upstream, client: 178.217.108.153, server: aiia.grandekos.com, request: "GET /blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1", upstream: "fastcgi://unix:/run/php8.2-fpm.sock:", host: "2.139.221.31:443"

	#--
	#
	a = line.split(" ",3)
	
	#--
	# Split line of log. Some values are skipped. They can be used in future.
	
	#-- Normal
	#XObj D1(4) ['78.128.112.74', '-', '-', '[02/Feb/2026:06:34:09 +0000] "SSH-2.0-Go" 400 157 "-" "-"\n']
	#XObj D2(2) ['[02/Feb/2026:06:34:09 +0000', '"SSH-2.0-Go" 400 157 "-" "-"\n']

	#-- ERROR
	#XObj D1( 4 ) ['2026/01/31', '03:32:38', '[error]', '28076#28076: *64310 FastCGI sent in stderr: "Primary script unknown" while reading response header from upstream, client: 8.222.225.103, server: aiia.grandekos.com, request: "GET /public/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1", upstream: "fastcgi://unix:/run/php8.2-fpm.sock:", host: "2.139.221.31:443"\n']
	
	#XObj D2( 1 ) ['28076#28076: *64310 FastCGI sent in stderr: "Primary script unknown" while reading response header from upstream, client: 8.222.225.103, server: aiia.grandekos.com, request: "GET /public/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1", upstream: "fastcgi://unix:/run/php8.2-fpm.sock:", host: "2.139.221.31:443"\n']
	
	#-- CRIT ERROR!
	# XObj D1( 4 ): ['2026/01/24', '01:57:34', '[crit]', '28076#28076: *34519 SSL_read() failed (SSL: error:0A000119:SSL routines::decryption failed or bad record mac error:0A000139:SSL routines::record layer failure) while waiting for request, client: 152.53.52.160, server: 0.0.0.0:443\n']
	# XObj D2( 1 ): ['28076#28076: *34519 SSL_read() failed (SSL: error:0A000119:SSL routines::decryption failed or bad record mac error:0A000139:SSL routines::record layer failure) while waiting for request, client: 152.53.52.160, server: 0.0.0.0:443\n']
	#--
	# (2.2.26) - addeding support to parse php error
	if a[2]=="[error]":
		#print("ERROR!")
		tmpdate = fix_datetime("{} {}".format( a[0], a[1] ))
		tmpobj = extract_log_fields( a[3] )
		#print("ERROR, fixed log: {}".format( tmpobj ))
		# output: 
		# {'client': '8.222.225.103,', 'server': 'aiia.grandekos.com,', 'request': 'GET /public/vendor.... HTTP/1.1', 'upstream': 'fastcgi://unix:/run/...:', 'host': '2.139.221.33'}
		# [02/Feb/2026:18:18:22 +0000]
		# [02/Feb/2026:18:18:22 +0000] "SSH-2.0-Go" 400 157 "-" "-"\n
		tmpdata = "{} \"{}\" 666 0 \"{}\" \"-\"\n".format(tmpdate,tmpobj['request'],tmpobj['server'])
		a[3] = tmpdata
		a[0] = tmpobj["client"]
		xobj['host']     = tmpobj['host']
		xobj['upstream'] = tmpobj['upstream']
		xobj['server']   = tmpobj['server']
	elif a[2]=="[crit]":
		print("CRITIC ERROR!")
		print("http.py => XObj line( {} ): {}".format( len(line_check),line ))
		tmpdate = fix_datetime("{} {}".format( a[0], a[1] ))
		tmpobj = extract_log_fields( a[3] )
		print("http.py => tmpobj",tmpobj)
		xobj["code"] = 667
		tmpdata = "{} \"{}\" 667 0 \"{}\" \"-\"\n".format(tmpdate,tmpobj['request'],tmpobj['server'])
		a[3] = tmpdata
		a[0] = tmpobj["client"]
		xobj['host']     = tmpobj['host']
		xobj['upstream'] = tmpobj['upstream']
		xobj['server']   = tmpobj['server']
	#	return None
	#else:
	#print("NOT ERROR!")
	xobj["ip"]   = a[0]
	tmp          = a[3]
	if xobj['code']==667:
		print("XObj D1( {} ): {}".format(len(a),a))
	a            = tmp.split("] ",1)
	if xobj['code']==667:
		print("XObj D2( {} ): {}".format(len(a),a))
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
	#print("DEBUG tmpdate: ",tmpdate)
	#
	xobj["date"]    = tmpdate                    # set date after generating crc
	if tmpdate != None:
		xobj["last_ts"] = strTs2Sec(tmpdate)     #
	xobj["hash"]    = crc                        #
	#
	return xobj
