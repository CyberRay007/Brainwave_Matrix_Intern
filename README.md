# Brainwave_Matrix_Intern
Phishing Link Scanner Project for Cybersecurity Internship
# Phishing Link Scanner

A Python-based cybersecurity tool to detect and flag potentially malicious or phishing URLs.  
This project was developed as part of my internship at Brainwave Matrix Intern.

---

#  Features
- Extracts and analyzes key features of URLs
- Detects suspicious patterns in domains and paths
- Flags risky URLs (e.g., containing -secure, login, verify)
- Supports batch scanning from CSV files
- Generates detailed reports (report.csv)
- Simple, beginner-friendly codebase for cybersecurity learners

---

# Project Structure
Brainwave_Matrix_Intern/
│── phishing_scanner.py # Main script
│── requirements.txt # Dependencies
│── sample_urls.csv # Example input file
│── report.csv # Example output file (generated after scan)
│── README.md # Project documentation

# Installation & Setup

# 1. Clone the repository

git clone (https://github.com/CyberRay007/Brainwave_Matrix_Intern.git)
cd Brainwave_Matrix_Intern
----

2. Create a virtual environment
python -m venv .venv


Activate it:

Windows (PowerShell):

.venv\Scripts\Activate


Linux/Mac:

source .venv/bin/activate

3. Install dependencies
pip install -r requirements.txt

# Usage
Scan a single URL
python phishing_scanner.py --url "http://Facebook.com/login"

Scan multiple URLs from CSV
python phishing_scanner.py --input_csv sample_urls.csv --output_csv report.csv


# Example sample_urls.csv:

url
https://www.microsoft.com
http://198.51.100.4/login
https://secure-paypa1.com/verify
http://example.com/update/account?user=you
https://bit.ly/3AbCdE
https://xn--pple-43d.com/login
https://accounts.google.com
http://sub1.sub2.sub3.sub4.domain.top/reset
https://mybank-secure-login.xyz/confirm
http://example.com/93485734987534987534

# Example Report Output

Generated report.csv:

url,domain,path,has_https,suspicious_chars,url_length,label
https://www.microsoft.com,www.microsoft.com,,True,False,25,Safe
http://198.51.100.4/login,198.51.100.4,/login,False,False,25,Suspicious
https://secure-paypa1.com/verify,secure-paypa1.com,/verify,True,True,32,Suspicious
http://example.com/update/account?user=you,example.com,/update/account,False,True,42,Phishing (High Risk)
https://bit.ly/3AbCdE,bit.ly,/3AbCdE,True,False,21,Safe
https://xn--pple-43d.com/login,xn--pple-43d.com,/login,True,True,30,Suspicious
https://accounts.google.com,accounts.google.com,,True,False,27,Safe
http://sub1.sub2.sub3.sub4.domain.top/reset,sub1.sub2.sub3.sub4.domain.top,/reset,False,False,43,Suspicious
https://mybank-secure-login.xyz/confirm,mybank-secure-login.xyz,/confirm,True,True,39,Suspicious
http://example.com/93485734987534987534,example.com,/93485734987534987534,False,False,39,Suspicious


# Requirements

Python 3.8+

Libraries:

requests

beautifulsoup4

pandas

pylance

Install them via:

pip install -r requirements.txt

Or you install them individually

# Internship Context

This project was built as part of my internship at Brainwave Matrix Intern, where I worked as a Cybersecurity Analyst & Ethical Hacker Intern.
The goal was to develop a beginner-friendly phishing link scanner to demonstrate practical applications of cybersecurity in detecting online threats.

📜 License

MIT License – feel free to use and modify this project, but please give credit.

🔖 Author

👨‍💻 Name (Raymond Favour Joshua)
📧 Email raymondjoshua004@gmail.com

🌐 GitHub: CyberRay007


---
