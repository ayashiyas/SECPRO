SECPRO: The Simple URL Vulnerability Scanner

SECPRO is a lightweight, web-based vulnerability scanner built with Flask and the OWASP ZAP API. It provides a simple user interface to perform passive, spider, and active security scans on web applications, making it easy to get started with basic security testing.


✨ Features
Intuitive Web UI: A clean and simple interface to start and view scan results.

Passive Scan: Get instant, non-invasive insights from the page.

Spider Scan: Crawls the target website to discover and map all accessible pages.

Active Scan: An optional, in-depth scan to actively test for common vulnerabilities like SQL Injection, XSS, and more.

Real-time Progress: A loading page with a progress bar lets you track the status of long-running active scans.


📦 Prerequisites

Before you can run this application, you need to have the following installed on your system:

Python 3

OWASP ZAP Desktop Client: The application communicates with the ZAP API, so you must have the ZAP desktop application running in the background.


🚀 Installation & Setup
Follow these steps to get the application up and running.

1. Clone the Repository
Clone your project from GitHub to your local machine.

git clone https://github.com/ayashiyas/SECPRO.git

cd SECPRO


2. Install Python Dependencies

Make sure you're in the project's root directory and install the required Python libraries.

pip install -r requirements.txt


Note: If you don't have a requirements.txt file, you can create one by running pip freeze > requirements.txt after installing Flask and python-owasp-zap.

3. Configure OWASP ZAP
Launch the OWASP ZAP Desktop Client.

Go to Tools > Options > API and ensure the API is enabled. The default API key in the Python code is '12345', so make sure this matches.

Ensure ZAP is running and the proxy is active on http://127.0.0.1:8080.

Alternatively, run ZAP from the command line for background operation:

You can start ZAP as a daemon (without the graphical user interface) for a more stable and hands-off experience. Open your terminal or command prompt, navigate to the ZAP installation directory, and run the following command.

On Windows:

zap.bat -daemon -config api.key=12345


On Linux/macOS:

./zap.sh -daemon -config api.key=12345


The -daemon flag tells ZAP to run in the background, and -config api.key=12345 sets the API key to match your application's configuration.

💻 How to Run (Development)
For local testing and development, you can simply run the Flask application directly.

python app.py


Open your web browser and navigate to http://127.0.0.1:5000 to access the application.



⚠️ Ethical Usage
WARNING: This tool is for educational and ethical security testing purposes only. You should only use it to scan websites that you own or have explicit, written permission to test. Unauthorized scanning of websites is illegal and unethical.

📜 License
This project is licensed under the MIT License. 
