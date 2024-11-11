import email
from email import policy
from email.parser import BytesParser

# Replace with the path to your email file
file_path = '/home/hp/Desktop/project_final_nov_7_2pm/sample.txt'
# Open the file and read the raw email content
with open(file_path, 'rb') as file:
    raw_email = file.read()

# Parse the raw email content
msg = BytesParser(policy=policy.default).parsebytes(raw_email)

# Extracting the plain text content
plain_text = None
html_content = None

for part in msg.iter_parts():
    # Extract plain text
    if part.get_content_type() == "text/plain":
        plain_text = part.get_payload(decode=True).decode(part.get_content_charset(), errors='ignore')
    
    # Extract HTML content
    elif part.get_content_type() == "text/html":
        html_content = part.get_payload(decode=True).decode(part.get_content_charset(), errors='ignore')

# Print the extracted content
print("Plain Text Content:")
print(plain_text)

print("\nHTML Content:")
print(html_content)

# Write the plain text content to a file
if plain_text:
    with open('extracted_plain_text.txt', 'w') as plain_text_file:
        plain_text_file.write(plain_text)
