#!/bin/bash

# Input string (without "and this")
input="2026/01/31 03:32:38"

# Extract date and time parts
date_str=$(echo "$input" | awk '{print $1}')
time_str=$(echo "$input" | awk '{print $2}')

# Parse date components
year=$(echo "$date_str" | awk -F/ '{print $1}')
month=$(echo "$date_str" | awk -F/ '{print $2}')
day=$(echo "$date_str" | awk -F/ '{print $3}')

# Convert month number to abbreviation
case "$month" in
  01) month_abbr="Jan" ;;
  02) month_abbr="Feb" ;;
  03) month_abbr="Mar" ;;
  04) month_abbr="Apr" ;;
  05) month_abbr="May" ;;
  06) month_abbr="Jun" ;;
  07) month_abbr="Jul" ;;
  08) month_abbr="Aug" ;;
  09) month_abbr="Sep" ;;
  10) month_abbr="Oct" ;;
  11) month_abbr="Nov" ;;
  12) month_abbr="Dec" ;;
  *) month_abbr="Unknown" ;;
esac

# Format the date and time
formatted_date="$day/$month_abbr/$year"
formatted_time="$time_str"

# Combine into final output
result="[${formatted_date}:${formatted_time} +0000]"

echo "$result"
