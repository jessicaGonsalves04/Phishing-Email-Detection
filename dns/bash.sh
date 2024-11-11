#!/bin/bash

# File to analyze (email header)
email_header_file="/home/hp/Desktop/project_final_nov_7_2pm/dns/email_header.txt"

# Capture file for DNS analysis
capture_file="/home/hp/Desktop/project_final_nov_7_2pm/dns/tmp/dns_capture1.pcap"

sudo touch "$capture_file"
sudo chmod 666 "$capture_file" 
# Directory for capture files
capture_dir="/home/hp/Desktop/project_final_nov_7_2pm/dns/tmp"

# Ensure the capture directory exists, if not create it
if [ ! -d "$capture_dir" ]; then
    echo "Directory $capture_dir does not exist. Creating it now..."
    mkdir -p "$capture_dir"
fi

# Ensure the directory is writable
if [ ! -w "$capture_dir" ]; then
    echo "Permission denied. You do not have write permissions for $capture_dir."
    exit 1
fi

# Ensure the capture file is created with proper permissions
if [ ! -f "$capture_file" ]; then
    sudo touch "$capture_file"
    sudo chmod 666 "$capture_file"  # Ensure the file is writable
fi

# Extract URLs from the email header
echo "Extracting URLs from email header..."
urls=($(grep -oP '(http|https)://[^ ]+' "$email_header_file" | awk -F/ '{print $3}'))

if [ ${#urls[@]} -eq 0 ]; then
    echo "No URLs found in email header."
    exit 0
fi

echo "URLs detected in email header: ${urls[@]}"

# Automatically detect network interface
interface=$(ifconfig | grep -o -E '^[^ ]+.*RUNNING' | grep '^w' | awk '{print $1}' | sed 's/://g')
if [ -z "$interface" ]; then
    interface="wlp2s0"
    echo "Interface auto-detection failed. Using default: $interface"
else
    echo "Detected network interface: $interface"
fi

# Capture DNS traffic
duration=15  # Adjust capture duration as needed
echo "Capturing DNS traffic on interface: $interface for $duration seconds..."
sudo tshark -i "$interface" -f "port 53" -w "$capture_file" -a duration:"$duration" 2>/dev/null

# Check if the capture file was created successfully
if [ ! -f "$capture_file" ]; then
    echo "Failed to capture DNS traffic."
    exit 1
fi

# Perform DNS lookups
echo "Performing DNS lookups using dig..."
for domain in "${urls[@]}"; do
    echo "Running dig for $domain..."
    dig "$domain" > /dev/null
done

# File to store the analysis results
output_file="/home/hp/Desktop/project_final_nov_7_2pm/dns/dns_analysis_results.txt"
> "$output_file"  # Clear the output file before appending

# Analyze DNS queries for each domain and store results in the output file
echo "Analyzing DNS traffic..." >> "$output_file"
for domain in "${urls[@]}"; do
    echo "Analyzing DNS traffic for: $domain" >> "$output_file"
    
    query_count=$(tshark -r "$capture_file" -Y "dns.qry.name == \"$domain\"" -T fields -e dns.a | wc -l)

    # Check for suspicious TLD
    tld=$(echo "$domain" | awk -F '.' '{print $NF}')
    if [[ " ${suspicious_tlds[*]} " == *" $tld "* ]]; then
        echo "Suspicious TLD detected: $domain ($tld)" >> "$output_file"
    fi

    if [ "$query_count" -gt 3 ]; then
        echo "Warning: Excessive DNS queries detected for $domain." >> "$output_file"
    elif [ "$query_count" -eq 0 ]; then
        echo "No DNS activity detected for $domain." >> "$output_file"
    else
        echo "$domain had $query_count DNS queries." >> "$output_file"
    fi

    echo "------------------------------------" >> "$output_file"
done


# Optionally, clean up
sudo tshark -r "$capture_file"   # Show capture details
# rm "$capture_file"          # Uncomment to delete capture file after use
