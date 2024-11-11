
from flask import Flask, request, jsonify
import openpyxl
from flask_cors import CORS
from datetime import datetime
import re
import os
import subprocess  # To run bash scripts

import email
from email import policy
from email.parser import BytesParser

app = Flask(__name__)
CORS(app)

# File path for Snort block list rules
BLOCK_LIST_RULE_FILE = '/etc/snort/rules/block_list.rules'
block_ip=None

# File paths
EXCEL_FILE = 'data.xlsx'
MALICIOUS_IP_FILE = '/etc/snort/rules/malicious_ips.txt'
SNORT_UPDATE_SCRIPT = '/etc/snort/rules/update_phishing_ips.sh'  # Path to your bash script
START_SNORT_SCRIPT = './start_snort.sh'  # Path to the start_snort.sh script
HPING3_SCRIPT = './run_hping3.sh'  # Path to the run_hping3.sh script
DNS_FOLDER = '/home/hp/Desktop/project_final_nov_7_2pm/dns' 
BASH_SCRIPT = '/home/hp/Desktop/project_final_nov_7_2pm/dns/bash.sh'
# Suspicious extensions and special characters
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.sh', '.js', '.vbs', '.com', '.cmd', '.zip', '.rar', '.7z', '.tar', '.gz']
SPECIAL_CHARS_REGEX = re.compile(r'[%$&^@]')
TEST_SCRIPT = '/home/hp/Desktop/project_final_nov_7_2pm/dns/text.sh'

email_body_file="/home/hp/Desktop/project_final_nov_7_2pm/dns/email_body.txt"

def block_ip_with_snort(ip_address):
    """
    Adds an IP address to the Snort block list and reloads Snort.
    
    :param ip_address: str - The IP address to block.
    :return: str - Success or error message.
    """
    # Rule format for blocking an IP in Snort
    rule = f"drop ip {ip_address} any -> any any (msg:\"Blocked IP {ip_address}\"; sid:1000001;)"
    
    try:
        # Append the rule to the block list file
        with open(BLOCK_LIST_RULE_FILE, 'a') as file:
            file.write(rule + "\n")
        
        print(f"Added block rule for IP: {ip_address}")
        
        # Run Snort command to reload the updated rules
        reload_command = ["sudo", "snort", "-R", BLOCK_LIST_RULE_FILE, "-A", "console", "-Q"]
        # result = subprocess.run(reload_command, capture_output=True, text=True)

        with open(MALICIOUS_IP_FILE, 'r') as malicious_file:
            existing_ips = malicious_file.readlines()
        
        # If IP is not already in the file, append it
        if ip_address + "\n" not in existing_ips:
            with open(MALICIOUS_IP_FILE, 'a') as malicious_file:
                malicious_file.write(ip_address + "\n")
            print(f"Added IP {ip_address} to malicious_ips.txt")
        else:
            print(f"IP {ip_address} is already in malicious_ips.txt")

        # print(f"Added IP {ip_address} to malicious_ips.txt")

        # Return True if the process was successful
        # print(f"Snort reloaded. IP {ip_address} is now blocked.")
        return True

    except Exception as e:
        print(f"Error blocking IP in Snort: {e}")
        # Return False in case of any errors
        return False
    
# Function to check if a filename is suspicious
def is_suspicious_filename(filename):
    # Check for special characters in the filename
    if SPECIAL_CHARS_REGEX.search(filename):
        return True
    
    # Check for suspicious extensions
    for ext in SUSPICIOUS_EXTENSIONS:
        if filename.endswith(ext):
            return True
    
    return False

# Function to extract the first IP address from email headers
def extract_first_ip_address(header):
    # Regular expression for IPv4
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, header)
    return match.group(0) if match else None

# Function to extract filenames from email headers
def extract_filenames(header):
    # Regular expression to find the filename in Content-Disposition
    filename_pattern = r'filename="([^"]+)"'
    filenames = re.findall(filename_pattern, header)
    return filenames

# Function to extract unique URLs from the email header
def extract_urls_from_header(header):
    # Regular expression to extract URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls = re.findall(url_pattern, header)
    
    # Return unique URLs by converting the list to a set
    return list(set(urls))

# Function to extract Return-Path and sender's email from header
def verify_return_path(header):
    # Regular expression to match the Return-Path email
    return_path_pattern = r'Return-Path: <([^>]+)>'
    
    # Refined pattern to capture the sender's email correctly, considering possible extra quotations or tags
    sender_pattern = r'From:.*?<([^>]+)>|From:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'

    return_path_match = re.search(return_path_pattern, header)
    sender_match = re.search(sender_pattern, header)

    return_path_email = return_path_match.group(1) if return_path_match else None
    sender_email = sender_match.group(1) if sender_match else None

    # If the sender match fails, try to grab the second capturing group (for more complex formats)
    if not sender_email and sender_match:
        sender_email = sender_match.group(2)

    # Verify if the Return-Path matches the sender's email
    is_match = (return_path_email == sender_email)

    return {
        'returnPath': return_path_email,
        'senderEmail': sender_email,
        'isMatch': is_match
    }

# Function to run nmap and store result in a file
def run_nmap_and_store(ip_address, filename='nmap_result.txt'):
    # Run the nmap command with the '-sL' flag for DNS resolution
    try:
        # Execute the nmap command and capture the output
        result = subprocess.run(['nmap', '-sL', ip_address], capture_output=True, text=True)
        
        # Check if nmap ran successfully
        if result.returncode == 0:
            # Write the output to a text file
            with open(filename, 'w') as file:
                file.write(result.stdout)
            print(f"nmap result stored in {filename}")
        else:
            print("Error in running nmap command:", result.stderr)
    except Exception as e:
        print("An error occurred while running nmap:", str(e))

# Function to compare email header and nmap result
def compare_with_email_header(email_header, filename='nmap_result.txt'):
    # Extract the IP address and expected hostname from the email header
    # Example of email header: "Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])"
    # email_ip = email_header.split("[")[1].split("]")[0]  # Extract IP from the header
    email_ip = extract_first_ip_address(email_header)
    email_hostname = email_header.split("from ")[1].split(" ")[0]  # Extract hostname from the header

    hostname=email_hostname
    dns_result=None

    print(f"Extracted IP address from email header: {email_ip}")
    print(f"Extracted hostname from email header: {email_hostname}")
    # Open the nmap result file and check for the matching hostname
    try:
        with open(filename, 'r') as file:
            nmap_result = file.read()

            print(f"nmap result from {filename}:")
            print(nmap_result)

            # Check if the IP matches and if the resolved hostname is correct
            if email_ip in nmap_result and email_hostname in nmap_result:
                print("The IP and hostname in the email header match the nmap result.")
                dns_result = "Result of reverse DNS lookup matches hostname from email header."
            else:
                print("Mismatch between email header and nmap result.")
                dns_result = "Result of reverse DNS lookup does not match hostname from email header."
    except FileNotFoundError:
        print(f"File {filename} not found. Please run nmap first.")
        dns_result = "nmap result file not found."
    
    # Return both hostname and the DNS lookup result
    return hostname, dns_result

def extract_authentication_results(header):
    # Regular expression patterns for DKIM, SPF, and DMARC
    dkim_pattern = r'dkim=(\w+)'  # Match DKIM result (e.g., "dkim=pass")
    spf_pattern = r'received-spf:\s*(\w+)'  # Match SPF result (e.g., "Received-SPF: pass")
    dmarc_pattern = r'dmarc=(\w+)'  # Match DMARC result (e.g., "dmarc=pass")

    # Extract DKIM result
    dkim_result = re.search(dkim_pattern, header, re.IGNORECASE)
    # Extract SPF result
    spf_result = re.search(spf_pattern, header, re.IGNORECASE)
    # Extract DMARC result
    dmarc_result = re.search(dmarc_pattern, header, re.IGNORECASE)

    # Return extracted results or 'N/A' if not found
    return {
        'dkim': dkim_result.group(1).strip() if dkim_result else 'N/A',
        'spf': spf_result.group(1).strip() if spf_result else 'N/A',
        'dmarc': dmarc_result.group(1).strip() if dmarc_result else 'N/A'
    }

# Function to save email header to a text file in the DNS folder
def save_header_to_dns_file(header, filename='email_header.txt'):
    # Create the file path
    filepath = os.path.join(DNS_FOLDER, filename)
    
    # Print the path for debugging
    print(f"Saving email header to {filepath}")
    
    try:
        with open(filepath, 'w') as file:
            file.write(header)
        print(f"Email header saved to {filepath}")
        return filepath
    except Exception as e:
        print(f"Error saving email header: {str(e)}")
        raise




@app.route('/append-to-excel', methods=['POST'])
def append_to_excel():
    data = request.json
    email_header = data.get('emailHeader')

    # Check if email_header is a string or bytes
    if isinstance(email_header, bytes):
        raw_email = email_header.decode('utf-8', errors='ignore')  # Decode bytes to string
    else:
        raw_email = str(email_header)  # If already a string, just use it

    if not email_header:
        return jsonify({'message': 'Email header is required.'}), 400

    try:
    
        # # Parse the raw email content
        # msg = BytesParser(policy=policy.default).parsebytes(email_header.encode())

        # # Extracting the plain text content
        # plain_text = None
        # html_content = None

        # for part in msg.iter_parts():
        #     # Extract plain text
        #     if part.get_content_type() == "text/plain":
        #         plain_text = part.get_payload(decode=True).decode(part.get_content_charset(), errors='ignore')
    
        # print("plain text:", plain_text)

        # # Open a file in write mode ('w') to store the output
        # with open(email_body_file, 'w') as file:
        #   file.write(f"plain text: {plain_text}\n")
        
        # Save the email header to a file in the DNS folder for bash script access
        dns_file_path = save_header_to_dns_file(email_header) 
        # Extract the first IP address from the header
        ip_address = extract_first_ip_address(email_header)
        block_ip=ip_address
        print("ip address: ", block_ip)

        if not ip_address:
            return jsonify({'message': 'No IP address found in the email header.'}), 400

        # Extract filenames from the email header
        filenames = extract_filenames(email_header)
        # Check for malicious filenames
        malicious_filenames = [filename for filename in filenames if is_suspicious_filename(filename)]
        print("Malicious Filenames Detected:", malicious_filenames)  # Add this line to log filenames

        # Extract URLs from the email header
        urls = extract_urls_from_header(email_header)
        print("Extracted URLs:", urls)  # Add this line to log URLs

        # Call the verify_return_path function and print the result
        return_path_result = verify_return_path(email_header)
        print("Return Path Verification Result:", return_path_result)  # Print the result of the Return-Path verification

        # Load the existing workbook or create a new one if it doesn't exist
        try:
            workbook = openpyxl.load_workbook(EXCEL_FILE)
            sheet = workbook.active
        except FileNotFoundError:
            workbook = openpyxl.Workbook()
            sheet = workbook.active
            sheet.append(['IP Address', 'Timestamp', 'Malicious Filenames', 'URLs'])  # Add header row for the new data

        # Append the extracted data to Excel
        sheet.append([ip_address, datetime.now(), ', '.join(malicious_filenames), ', '.join(urls)])  # Join malicious filenames and URLs into strings
        workbook.save(EXCEL_FILE)

        # Run the nmap command to resolve the IP address and store the result
        run_nmap_and_store(ip_address)
        # Compare the email header information with nmap result and extract hostname and DNS result
        hostname, dns_result = compare_with_email_header(email_header)

        # Extract DKIM, SPF, and DMARC results
        auth_results = extract_authentication_results(email_header)
        print("Authentication Results:", auth_results)  # Log the authentication results

        # Run the bash script to update Snort rules
        try:
            subprocess.run([SNORT_UPDATE_SCRIPT], check=True)
        except subprocess.CalledProcessError as e:
            return jsonify({'message': f'Error updating Snort rules: {str(e)}'}), 500

        # Open a new terminal and run the start_snort.sh script
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'./{START_SNORT_SCRIPT}; exec bash'])  # Adjust for your terminal

        # Open a new terminal and run the hping3 script with the extracted IP
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'./{HPING3_SCRIPT} {ip_address}; exec bash'])  # Adjust for your terminal
        # subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'{BASH_SCRIPT} {ip_address}; exec bash'])  # Adjust for your terminal
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'sudo {BASH_SCRIPT} {ip_address}; exec bash'])
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f'{TEST_SCRIPT} {ip_address}; exec bash'])


        return jsonify({
        'message': 'IP address appended, urls stored, Snort started in a new terminal, and hping3 attack triggered in a new terminal.',
        'extractedIP': ip_address,
        'maliciousFilenames': malicious_filenames,  # Return the malicious filenames in the response
        'extractedURLs': urls,  # Return the extracted URLs in the response
        'isReturnPathMatch': return_path_result['isMatch'],
        'returnPath': return_path_result['returnPath'],
        'senderEmail': return_path_result['senderEmail'],
        'returnPathVerificationResult': f"Return-Path: {return_path_result['returnPath']}, Sender Email: {return_path_result['senderEmail']}, Match: {return_path_result['isMatch']}",  # New field
        'hostname': hostname,
        'dnsResult': dns_result, # This will now show whether the reverse DNS matches the email header's hostname
        'dkim': auth_results['dkim'],
        'spf': auth_results['spf'],
        'dmarc': auth_results['dmarc']
    }), 200
    except Exception as e:
        print(f"Error: {str(e)}")  # Log the error message to the console
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500

@app.route('/get-snort-alerts', methods=['GET'])
def get_snort_alerts():
    try:
        with open('/var/log/snort/snort.alert.fast', 'r') as file:
            alerts = file.readlines()
        return jsonify({'alerts': alerts})
    except FileNotFoundError:
        return jsonify({'alerts': []}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/get-dns-analysis-results', methods=['GET'])
def get_dns_analysis_results():
    try:
        with open('/home/hp/Desktop/project_final_nov_7_2pm/dns/dns_analysis_results.txt', 'r') as file:
            dns_analysis_results = file.read()
        return jsonify({"dnsResults": dns_analysis_results})
    except Exception as e:
        return jsonify({"error": f"Error reading DNS analysis results: {str(e)}"}), 500

@app.route('/get-text-analysis-results', methods=['GET'])
def get_text_analysis_results():
    try:
        with open('/home/hp/Desktop/project_final_nov_7_2pm/dns/analysis_results.txt', 'r') as file:
            text_analysis_results = file.read()
        return jsonify({"textResults": text_analysis_results})
    except Exception as e:
        return jsonify({"error": f"Error reading text analysis results: {str(e)}"}), 500

@app.route('/block-ip', methods=['POST'])
def block_ip():
    # Get the IP address from the incoming request's JSON body
    data = request.get_json()
    ip_address = data.get('ip')
    
    if not ip_address:
        return jsonify({'message': 'No IP address provided'}), 400
    
    # Print the IP address for debugging
    print(f"------------ Block IP ------------ {ip_address}")
    
     # Call block_ip_with_snort function
    if block_ip_with_snort(ip_address):
        # Return success message if the IP was successfully blocked
        return jsonify({'message': f"IP {ip_address} successfully blocked in Snort.", 'status': 'success'})
    else:
        # Return error message if there was an issue blocking the IP
        return jsonify({'message': f"Error blocking IP {ip_address} in Snort.", 'status': 'error'}), 500


if __name__ == '__main__':
    app.run(debug=True)
