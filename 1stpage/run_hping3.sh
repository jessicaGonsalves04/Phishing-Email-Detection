#!/bin/bash
# run_hping3.sh - Script to run hping3 attack using provided IP address

if [ -z "$1" ]; then
  echo "No IP address provided."
  exit 1
fi

TARGET_IP="$1"
sudo truncate -s 0 /var/log/snort/snort.alert.fast
sleep 5

# Run hping3 with the extracted IP address (SYN packet on port 80)
sudo hping3 -c 1 -a "$TARGET_IP" -S 192.168.1.10 -p 80

# Wait for Snort to capture the packet
sleep 5

# Assuming Snort logs are stored in /var/log/snort/snort.alert.json
sudo pkill snort  # Stop snort after the attack


#chmod +x /path/to/run_hping3.sh
