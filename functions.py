import re, time, os
import zlib
from datetime import datetime
# info for arguments: https://docs.python.org/3/library/time.html#time.strftime
#
def strTs2Sec( strTs, args="%d/%b/%Y:%H:%M:%S %z" ):
	# 10/Oct/2021 19:30:42 +0100
	#s = "16/08/2013 09:51:43" "%d/%b/%Y:%H:%M:%S %z"
	#d = datetime.strptime("16/08/2013 09:51:43", "%d/%m/%Y:%H:%M:%S %z")
	d = datetime.strptime(strTs, args)
	return int(time.mktime(d.timetuple()))

#
def crc32b(text):
	return "%x"%(zlib.crc32(text) & 0xFFFFFFFF)

#
def rmatch(input,regex):
	x = re.match( regex, input )
	if x != None:
		return x
	else:
		return False

#
def pmatch(input,regex):
	ret=[]
	a = re.findall( regex, input, flags=re.IGNORECASE )
	#print("pmatch a: {}".format(a))
	if a is not None:
		for v in a:
			ret.append( v )
	return ret

#
def arr_dump(a):
	cnt=0
	for k in a:
		if isinstance(a,list):
			print("k[{}] = {}".format(cnt,a[cnt]))
		else:
			print("k: {} => {}".format(k, a[k]))
		cnt+=1

#
def arr_index(a,v):
	try:
		return a.index(v)
	except:
		return None
#
def file_exists( filename:str ) -> bool:
	return os.path.exists( filename )
#
def file_write( filename, data, overwrite=False ):
	f=None
	try:
		if file_exists(filename) and overwrite==True:
			f = open(filename,"w")
			f.seek(0)
			f.truncate()
		elif file_exists(filename)==False:
			f = open(filename,"w")
		else:
			f = open(filename,"a")
		f.write("{}".format( data ))
		f.close()
	except Exception as E:
		print("ERROR: file_write() on file: {}, len: {}, E: {}".format( filename, len(data), E ))

#
def file_overline( filename, xobj, at, isString=False ):
	#--
	#
	if os.path.exists( filename )==False:
		return False;
	
	lines=[]
	with open(filename,'r') as f:
		lines = f.readlines()
	#
	with open(filename,'w') as f:
		for i,line in enumerate(lines,0):
			if i==at:
				if isString==False:
					f.writelines( "{}\n".format( json.dumps(xobj) ) )
				else:
					f.writelines( "{}\n".format( line.strip() ) )
			else:
				f.writelines( "{}\n".format( line.strip() ) )
