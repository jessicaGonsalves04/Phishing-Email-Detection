#!/bin/bash
# start_snort.sh - Script to start Snort and restart the service

# Restart Snort service
sudo systemctl restart snort

# Test Snort configuration
sudo snort -T -c /etc/snort/snort.conf

# Start Snort on the specified interface and display output to console
# sudo snort -A console -c /etc/snort/snort.conf -i wlp0s20f3

sudo snort -q -D -i wlp0s20f3 -A json -c /etc/snort/snort.conf -l /var/log/snort

#chmod +x /path/to/start_snort.sh
