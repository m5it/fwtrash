import re

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


log_line = (
    '"28076#28076: *64310 FastCGI sent in stderr: "Primary script unknown" while reading response header from upstream, '
    'client: 8.222.225.103, server: aiia.grandekos.com, '
    'request: "GET /public/vendor.... HTTP/1.1", upstream: "fastcgi://unix:/run/...:", host: "2.139.221.33"'
)

fields = extract_log_fields(log_line)
print(fields)
