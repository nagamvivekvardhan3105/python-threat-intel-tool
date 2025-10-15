# Threat Intelligence and Analysis Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A professional-grade, command-line tool developed in Python to automate the enrichment and security analysis of IP addresses. This tool gathers data from external APIs, enriches it with contextual information, and generates secure, auditable reports with a strong focus on the CIA Triad (Confidentiality, Integrity, and Availability).



## Key Features

- **Threat Intelligence Integration:** Fetches IP reputation data from the VirusTotal API.
- **Data Enrichment:** Enriches findings with **WHOIS** ownership data and reverse **DNS** lookups.
- **Confidentiality:** Implemented AES encryption using the `cryptography` library to protect sensitive report data at rest.
- **Integrity:** Ensures report authenticity by generating and verifying **SHA256 hashes** to detect any form of tampering.
- **Availability:** Engineered for resilience with network **timeouts** and robust **error handling** to manage API or network failures gracefully.
- **Privacy Safeguards:** Automatically detects and filters private/internal (RFC1918) IP addresses to prevent internal network data leakage.
- **Professional-Grade Practices:** Features a detailed logging audit trail, secure API key management with `.env` files, and flexible input via command-line arguments.

---

## Getting Started

Follow these instructions to get a copy of the project up and running on your local machine.

### Prerequisites

- Python 3.8+
- Pip (Python package installer)

### Installation

1.  **Clone the repository**
    ```sh
    git clone [https://github.com/your-username/your-repository-name.git](https://github.com/your-username/your-repository-name.git)
    ```
2.  **Navigate to the project directory**
    ```sh
    cd python-threat-intel-tool
    ```
3.  **Install the required libraries**
    ```sh
    pip install -r requirements.txt
    ```

---

## Configuration

Before running the tool, you must configure your secret keys.

1.  **VirusTotal API Key:**
    - Create a file named `.env` in the root directory.
    - Add your VirusTotal API key to this file in the following format:
      ```
      VT_API_KEY=your_virustotal_api_key_here
      ```

2.  **Encryption Key:**
    - Run the key generation script once to create your `secret.key` file. This key is used to encrypt and decrypt your reports.
      ```sh
      python generate_key.py
      ```
    - **Important:** Keep your `secret.key` file safe and do not share it.

---

## Usage

The tool can be run from the command line with the following options.

### To Analyze a Single IP
```sh
python ip_analyzer.py -i 8.8.8.8

To Analyze a List of IPs from a File
Make sure you have a file named ips.txt with one IP address per line.

Bash

python ip_analyzer.py -f ips.txt
Understanding the Output
The tool generates three primary output files:

ip_reputation_results.csv.enc: An encrypted file containing the CSV report. This file cannot be read without decryption.

ip_reputation_results.csv.enc.sha256: A text file containing the SHA256 hash of the encrypted report, used to verify its integrity.

app.log: A detailed, timestamped log file that serves as an audit trail for all actions and errors.

To Decrypt and View a Report
Bash

python decrypt_report.py
To Verify a Report's Integrity
Bash

python verify_report.py
License
This project is licensed under the MIT License - see the LICENSE.md file for details.