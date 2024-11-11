function submitForm() {
    const emailHeader = document.querySelector('.email-header').value; // Get the value from the input field
    if (emailHeader) {
        fetch('http://localhost:5000/append-to-excel', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ emailHeader: emailHeader })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            alert(data.message);
            
             // Store malicious filenames in local storage
            if (data.maliciousFilenames && data.maliciousFilenames.length > 0) {
                localStorage.setItem('maliciousFilenames', JSON.stringify(data.maliciousFilenames));
            } else {
                localStorage.setItem('maliciousFilenames', JSON.stringify([]));  // Set to empty array
            }

            // Get the IP address from local storage
            localStorage.setItem('extractedIP', data.extractedIP || 'NO IP found');


            // Store the Return-Path and Sender-Email in local storage
            localStorage.setItem('returnPath', data.returnPath || 'No Return-Path found');
            localStorage.setItem('senderEmail', data.senderEmail || 'No sender email found');
            localStorage.setItem('isReturnPathMatch', data.isReturnPathMatch);

            // Store the Return-Path verification result
            localStorage.setItem('returnPathVerificationResult', data.returnPathVerificationResult || 'No verification result available');

            // Store the Hostname and DNS result
            localStorage.setItem('hostname', data.hostname || 'No hostname found');
            localStorage.setItem('dnsResult', data.dnsResult || 'No DNS result available');

            // Store DKIM, SPF, and DMARC results
            localStorage.setItem('dkim', data.dkim || 'N/A');
            localStorage.setItem('spf', data.spf || 'N/A');
            localStorage.setItem('dmarc', data.dmarc || 'N/A');

        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while submitting the data.');
        });
    } else {
        alert('Please enter the email header before submitting.');
    }
}

  
function viewReport() {
    // Replace 'your-page-url.html' with the actual URL of the page you want to navigate to
    //console.log('View Report clicked');
    window.location.href = './index2.html';
}
function loadAlerts() {
    fetch('http://localhost:5000/get-snort-alerts')
        .then(response => response.json())
        .then(data => {
            const alertList = document.getElementById('alert-list');
            alertList.innerHTML = '';

            // Check for Snort alerts
            if (data.alerts && data.alerts.length > 0) {
                data.alerts.forEach((alert, index) => {
                    if (index % 2 === 0) {
                        const listItem = document.createElement('li');
                        listItem.textContent = alert;
                        alertList.appendChild(listItem);
                    }
                });
            } else {
                const noAlertsMessage = document.createElement('li');
                noAlertsMessage.textContent = 'No alerts found';
                alertList.appendChild(noAlertsMessage);
            }

            // Check for malicious filenames from local storage
            const maliciousFilenames = JSON.parse(localStorage.getItem('maliciousFilenames'));
            if (maliciousFilenames && Array.isArray(maliciousFilenames) && maliciousFilenames.length > 0) {
                const maliciousMessage = document.createElement('li');
                maliciousMessage.textContent = `Alert: Malicious filenames detected: ${maliciousFilenames.join(', ')}`;
                alertList.appendChild(maliciousMessage);
            } else {
                const safeMessage = document.createElement('li');
                safeMessage.textContent = 'No malicious files detected.';
                alertList.appendChild(safeMessage);
            }

            // Get the stored data from localStorage
            const returnPath = localStorage.getItem('returnPath');
            const senderEmail = localStorage.getItem('senderEmail');
            const isMatch = JSON.parse(localStorage.getItem('isReturnPathMatch'));
            // const returnPathVerificationResult = localStorage.getItem('returnPathVerificationResult');  // Get the stored result
            const hostname = localStorage.getItem('hostname');
            const dnsResult = localStorage.getItem('dnsResult');
            // Display DKIM, SPF, and DMARC results
            const dkim = localStorage.getItem('dkim');
            const spf = localStorage.getItem('spf');
            const dmarc = localStorage.getItem('dmarc');
            
            const returnPathMessage = document.createElement('li');
            returnPathMessage.textContent = `Return-Path: ${returnPath}`;
            alertList.appendChild(returnPathMessage);

            const senderEmailMessage = document.createElement('li');
            senderEmailMessage.textContent = `Sender Email: ${senderEmail}`;
            alertList.appendChild(senderEmailMessage);

            // Display the match result for Return Path Verification
            const verificationMessage = document.createElement('li');
            verificationMessage.textContent = `Return Path Verification Result: ${isMatch ? 'True' : 'False'}`;
            alertList.appendChild(verificationMessage);

            // // Display the Return-Path verification results
            // const verificationMessage = document.createElement('li');
            // verificationMessage.textContent = `Return Path Verification Result: ${returnPathVerificationResult}`;
            // alertList.appendChild(verificationMessage);

            // Display Hostname and DNS result
            const hostnameMessage = document.createElement('li');
            hostnameMessage.textContent = `Hostname from DNS: ${hostname}`;
            alertList.appendChild(hostnameMessage);

            const dnsResultMessage = document.createElement('li');
            dnsResultMessage.textContent = `DNS Lookup Result: ${dnsResult}`;
            alertList.appendChild(dnsResultMessage);

            const dkimMessage = document.createElement('li');
            dkimMessage.textContent = `DKIM Verification: ${dkim}`;
            alertList.appendChild(dkimMessage);

            const spfMessage = document.createElement('li');
            spfMessage.textContent = `SPF Verification: ${spf}`;
            alertList.appendChild(spfMessage);

            const dmarcMessage = document.createElement('li');
            dmarcMessage.textContent = `DMARC Verification: ${dmarc}`;
            alertList.appendChild(dmarcMessage);
            
        })
        .catch(error => {
            console.error('Error fetching alerts:', error);
            const alertList = document.getElementById('alert-list');
            const errorMessage = document.createElement('li');
            errorMessage.textContent = 'Error fetching alerts';
            alertList.appendChild(errorMessage);
        });

     // Fetch DNS analysis results and append to the list
    fetch('http://localhost:5000/get-dns-analysis-results')
        .then(response => response.json())
        .then(data => {
            const alertList = document.getElementById('alert-list');
            if (data.dnsResults) {
                appendMessage(alertList, `DNS Analysis Results: ${data.dnsResults}`);
            } else {
                 appendMessage(alertList, 'No DNS analysis results available.');
            }
        })
        .catch(error => {
             console.error('Error fetching DNS analysis results:', error);
             const alertList = document.getElementById('alert-list');
             appendMessage(alertList, 'Error fetching DNS analysis results.');
         });

    // Fetch Text Analysis results and append to the list
    fetch('http://localhost:5000/get-text-analysis-results')
        .then(response => response.json())
        .then(data => {
           const alertList = document.getElementById('alert-list');
            if (data.textResults) {
              appendMessage(alertList, `Text Analysis Results: ${data.textResults}`);
            } else {
                appendMessage(alertList, 'No Text Analysis results available.');
            }
        })
        .catch(error => {
            console.error('Error fetching Text Analysis results:', error);
            const alertList = document.getElementById('alert-list');
            appendMessage(alertList, 'Error fetching Text Analysis results.');
        });

}

// Helper function to append messages
function appendMessage(alertList, message) {
    const listItem = document.createElement('li');
    listItem.textContent = message;
    alertList.appendChild(listItem);
}

// function block_ip() {
//     // Retrieve the stored IP address from local storage
//     const storedIpAddress = localStorage.getItem('extractedIP');
//     console.log("Stored IP Address: ", storedIpAddress); // Debugging line

//     if (!storedIpAddress || storedIpAddress === 'NO IP found') {
//         alert('No IP address found to block.');
//         return;
//     }

//     fetch('http://localhost:5000/block-ip', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json'
//         },
//         body: JSON.stringify({ ip: storedIpAddress }) // Use the retrieved IP address
//     })
//     .then(response => response.json())
//     .then(data => {
//         console.log("Response from backend:", data); // Add this line to debug
//         if (data.status === 'success') {
//             alert(data.message || 'IP address blocked successfully.');
//         } else {
//             alert(data.message || 'Failed to block IP address.');
//         }
//     })
//     .catch(error => {
//         console.error('Error:', error);
//         alert('An error occurred while blocking the IP address.');
//     });
// }

function block_ip() {
    // Retrieve the stored IP address from local storage
    const storedIpAddress = localStorage.getItem('extractedIP');
    console.log("Stored IP Address: ", storedIpAddress); // Debugging line

    // Check if the IP address exists
    if (!storedIpAddress || storedIpAddress === 'NO IP found') {
        alert('No IP address found to block.');
        return;
    }

    // Send a POST request to the backend to block the IP
    fetch('http://localhost:5000/block-ip', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ip: storedIpAddress }) // Use the retrieved IP address
    })
    .then(response => {
        // Check if the response is ok (status 200)
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json(); // Parse the JSON response
    })
    .then(data => {
        // Show the message from the backend
        alert(data.message || 'IP address blocked successfully.');
    })
    .catch(error => {
        // Handle any errors that occur during the fetch or response parsing
        console.error('Error:', error);
        alert('An error occurred while blocking the IP address.');
    });
}
