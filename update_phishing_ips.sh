#!/bin/bash
# Script to read malicious IPs from a file and update the Snort rule file

# Define the source file and target Snort rule file
MALICIOUS_IP_FILE="/etc/snort/rules/malicious_ips.txt"
RULE_FILE="/etc/snort/rules/phishing_ips.rules"

# Read IPs from file and concatenate into a comma-separated list
IPS=$(paste -sd "," $MALICIOUS_IP_FILE)

# Backup the existing rule file
cp $RULE_FILE ${RULE_FILE}.bak

# Update the Snort rule file with the IPs
echo "ipvar PHISHING_IPS [$IPS]" > $RULE_FILE
echo 'alert ip $PHISHING_IPS any -> any any (msg:"Phishing Attempt Detected from Known Phishing IP"; sid:1000005; rev:1;)' >> $RULE_FILE

echo "Snort rules updated with IPs: $IPS"
