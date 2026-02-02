def format_datetime(input_str):
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
#--
#
input_str = "2026/01/31 03:32:38"
output = format_datetime(input_str)
print(output)
