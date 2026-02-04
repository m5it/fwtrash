import os, json
from functions import *
#--
#
def Load_option( opts:list={} ):
	#
	opt_file_option = opts['file'] if "file" in opts else None
	#
	if opt_file_option==None or os.path.exists( opt_file_option )==False:
		return {}
	
	print("loading options...")
	
	#--
	with open( opt_file_option ) as f:
		return json.loads( f.read() )
	return None
	

#--
#
def Load_allowedips( ips:list, opts:list={} ):
	#
	opt_file_allowedips = opts['file'] if "file" in opts else None
	#
	ret = ips
	#
	if os.path.exists( opt_file_allowedips )==False:
		return ret;
	#
	with open(opt_file_allowedips) as f:
		for ip in f:
			if arr_index(ret, ip.strip())==None:
				#g_allowedips.append( ip.strip() )
				ret.append( ip.strip() )
	print("Loaded allowedips {}".format( len(ret) ))
	return ret


#--
#
def Load_badips( ips:list, opts:list={} ):
	#
	opt_file_badips = opts['file'] if "file" in opts else None
	#
	ret = ips
	#
	if os.path.exists( opt_file_badips )==False:
		return ret;
	#--
	with open(opt_file_badips) as f:
		for line in f:
			badip = line.strip().split(" ")[1]
			if arr_index(ret, badip)==None:
				ret.append( badip )
	print("Loaded badips {}".format( len(ret) ))
	return ret

#--
#
def Load_rules( rules:list, opts:list={} ):
	#
	opt_file_rules = opts['file'] if "file" in opts else None
	print("Load_rules() opt_file_rules: {}".format(opt_file_rules))
	#
	ret = rules
	#
	if os.path.exists( opt_file_rules )==False:
		return ret;
	#--
	with open(opt_file_rules) as f:
		for line in f:
			if rmatch(line,r'^#|\s*$'):
				continue
			if rmatch(line,".*\\#.*")!=False: # scrap only line if commented somewhere
				ret.append( json.loads( pmatch(line,".*(?=\\#)")[0] ) )
			else:
				ret.append( json.loads( line ) )
	print("Loaded rules {}".format( len(ret) ))
	return ret

#--
#
def Load_trash( trash:list, opts:list={} ):
	#
	opt_file_trash = opts['file'] if "file" in opts else None
	#
	ret = trash
	#
	if os.path.exists( opt_file_trash )==False:
		return ret;
	#--
	with open(opt_file_trash) as f:
		for dump in f:
			ret.append( json.loads(dump) )
	print("Loaded trash {}".format( len(ret) ))
	return ret

#-------- END of FILE --------
