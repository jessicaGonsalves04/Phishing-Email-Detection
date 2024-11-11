# #!/bin/bash

# # File containing the email header
# email_header_file="/home/hp/Desktop/project_final_nov_7_2pm/dns/email_header.txt"

# # File to store the extracted body
# email_body_file="/home/hp/Desktop/project_final_nov_7_2pm/dns/email_body.txt"

# # Dictionary of suspicious words
# suspicious_keywords=("offer" "sale" "insurance" "discount" "free" "limited" "urgent" "win" 
#                      "????????" "!!!!!!!" "make money" "click this link to get money" 
#                      "hurry up!" "hurry up" "final notice" "attention" "immediate action required" 
#                      "your account has been compromised" "verify your identity" 
#                      "confirm your account" "credit card update needed" "pending transactions" 
#                      "refund available" "unusual activity detected" "payment confirmation" 
#                      "claim your prize" "you've won")

# # Extract the email body from the email header using regex
# echo "Extracting email body from header..."

# # Here, we extract text after the boundary markers for text parts
# # Assume the body starts after a boundary like 'Content-Type: text/plain' or similar
# # Adjust this regex based on actual header structure
# sed -n '/Content-Type: text\/plain/,/Content-Transfer-Encoding: base64/p' "$email_header_file" | sed -e '1d' -e '/Content-Transfer-Encoding/d' > "$email_body_file"

# # Check if the body was extracted successfully
# if [ ! -s "$email_body_file" ]; then
#     echo "Failed to extract body from email header."
#     exit 1
# fi

# echo "Email body extracted to $email_body_file."

# # Read the body content into a variable
# email_body=$(cat "$email_body_file")

# # Function to check for suspicious words
# check_keywords() {
#     local content="$1"
#     for word in "${suspicious_keywords[@]}"; do
#         if echo "$content" | grep -i -q "\b$word\b"; then
#             echo "Potentially Malicious.Suspicious word detected: $word"
#         fi
#     done
# }

# # Function to check for excessive punctuation
# check_punctuation() {
#     local content="$1"
#     exclamation_count=$(echo "$content" | grep -o '!' | wc -l)
#     dot_count=$(echo "$content" | grep -o '\.' | wc -l)
#     if [ "$exclamation_count" -gt 5 ]; then
#         echo "Potentially Maliciouis as excessive exclamation marks detected: $exclamation_count"
#     fi
#     if [ "$dot_count" -gt 10 ]; then
#         echo "Might be Malicious as excessive dots detected: $dot_count"
#     fi
# }

# # Function to check for spelling mistakes using a basic dictionary (you can use a more advanced spell checker)
# check_spelling() {
#     local content="$1"
#     echo "$content" | aspell list | tee /dev/null | wc -l
#     if [ "$(echo "$content" | aspell list | tee /dev/null | wc -l)" -gt 5 ]; then
#         echo "Potentially malicious as spelling mistakes detected."
#     fi
# }

# # Run checks on the extracted body content
# echo "Performing text analysis on the email body..."

# check_keywords "$email_body"
# check_punctuation "$email_body"
# check_spelling "$email_body"

# # Final decision based on analysis
# echo "------------------------------------"
# echo "Analysis complete."


#!/bin/bash

# File containing the email header
email_header_file="/home/hp/Desktop/project_final_nov_7_2pm/dns/email_header.txt"

# File to store the extracted body
email_body_file="/home/hp/Desktop/project_final_nov_7_2pm/dns/email_body.txt"

# File to store the analysis results
analysis_results_file="/home/hp/Desktop/project_final_nov_7_2pm/dns/analysis_results.txt"
echo "" > "$analysis_results_file"

# Dictionary of suspicious words
suspicious_keywords=("offer" "sale" "insurance" "discount" "free" "limited" "urgent" "win" 
                     "????????" "!!!!!!!" "make money" "click this link to get money" 
                     "hurry up!" "hurry up" "final notice" "attention" "immediate action required" 
                     "your account has been compromised" "verify your identity" 
                     "confirm your account" "credit card update needed" "pending transactions" 
                     "refund available" "unusual activity detected" "payment confirmation" 
                     "claim your prize" "you've won")

# Function to extract the email body from the header
extract_email_body() {
    local email_header_file="$1"
    local email_body_file="$2"
    
    # Check if the email contains a 'Content-Type' header for text/plain
    # Extract content after "Content-Type: text/plain" until we hit a boundary marker or encoding type
    awk '
    BEGIN {
        body_started = 0;
    }
    /Content-Type: text\/plain/ {
        body_started = 1;
    }
    body_started == 1 && /Content-Transfer-Encoding: base64/ {
        body_started = 0;
    }
    body_started == 1 {
        print $0
    }
    ' "$email_header_file" > "$email_body_file"
}





# Extract the email body from the email header
echo "Extracting email body from header..."
extract_email_body "$email_header_file" "$email_body_file"

# Check if the body was extracted successfully
if [ ! -s "$email_body_file" ]; then
    echo "Failed to extract body from email header."
    # exit 1
fi

echo "Email body extracted to $email_body_file."

# Read the body content into a variable
email_body=$(cat "$email_body_file")
echo "$email_body"

# Function to check for suspicious words
check_keywords() {
    local content="$1"
    for word in "${suspicious_keywords[@]}"; do
        if echo "$content" | grep -i -q "\b$word\b"; then
            echo "Potentially Malicious. Suspicious word detected: $word" | tee -a "$analysis_results_file"
        fi
    done
}

# Function to check for excessive punctuation
check_punctuation() {
    local content="$1"
    exclamation_count=$(echo "$content" | grep -o '!' | wc -l)
    dot_count=$(echo "$content" | grep -o '\.' | wc -l)
    if [ "$exclamation_count" -gt 5 ]; then
        echo "Potentially Malicious as excessive exclamation marks detected: $exclamation_count" | tee -a "$analysis_results_file"
    fi
    if [ "$dot_count" -gt 10 ]; then
        echo "Might be Malicious as excessive dots detected: $dot_count" | tee -a "$analysis_results_file"
    fi
}

# Function to check for spelling mistakes using a basic dictionary (you can use a more advanced spell checker)
check_spelling() {
    local content="$1"
    echo "$content" | aspell list | tee /dev/null | wc -l
    if [ "$(echo "$content" | aspell list | tee /dev/null | wc -l)" -gt 5 ]; then
        echo "Potentially malicious as spelling mistakes detected." | tee -a "$analysis_results_file"
    fi
}

# Run checks on the extracted body content
echo "Performing text analysis on the email body..." | tee -a "$analysis_results_file"

check_keywords "$email_body"
check_punctuation "$email_body"
check_spelling "$email_body"

# Final decision based on analysis
echo "------------------------------------" | tee -a "$analysis_results_file"
echo "Analysis complete."| tee -a "$analysis_results_file"
