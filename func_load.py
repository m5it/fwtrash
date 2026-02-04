import os

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
		for line in f:
			badip = line.strip().split(" ")[1]
			if arr_index(g_badips, badip)==None:
				g_badips.append( badip )
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
