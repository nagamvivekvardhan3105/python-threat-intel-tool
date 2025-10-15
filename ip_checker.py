# ip_analyzer.py

import requests
import json
import time
import os
import csv
import socket
import logging
import argparse
import io
import hashlib
import ipaddress
from ipwhois import IPWhois
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# --- 1. CONFIGURE LOGGING (AUDIT TRAIL) ---
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- 2. LOAD API KEY SECURELY ---
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    logging.critical("API key not found. Set VT_API_KEY in your .env file.")
    raise ValueError("API key not found. Set VT_API_KEY in your .env file")

# --- 3. DATA ENRICHMENT & ANALYSIS FUNCTIONS ---

def is_private_ip(ip_string):
    """Checks if an IP address is in a private (RFC1918) range."""
    try:
        ip = ipaddress.ip_address(ip_string)
        return ip.is_private
    except ValueError:
        logging.warning(f"Invalid IP address format: '{ip_string}'.")
        return True # Treat invalid IPs as something to skip

def get_whois_info(ip_address):
    """Gets the AS Owner for an IP address and returns it."""
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap()
        return results.get('asn_description', 'N/A')
    except Exception as e:
        logging.warning(f"Could not get WHOIS info for {ip_address}: {e}")
        return "WHOIS Error"

def get_hostname(ip_address):
    """Gets the hostname for an IP address and returns it."""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Hostname N/A"

def check_ip_reputation(ip_address):
    """Checks VirusTotal, validates the response, and returns the malicious count."""
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        result = response.json()
        
        data = result.get('data', {})
        attributes = data.get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        
        return malicious_count
        
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error checking {ip_address}: {e}")
        return -1
    except KeyError:
        logging.warning(f"Unexpected API response format for {ip_address}.")
        return -1

# --- 4. MAIN SCRIPT LOGIC ---
def main():
    parser = argparse.ArgumentParser(description="IP Reputation and Enrichment Tool with Encrypted and Hashed Output.")
    parser.add_argument("-i", "--ip", help="Check a single IP address.")
    parser.add_argument("-f", "--file", help="Check a list of IPs from a file.")
    args = parser.parse_args()

    logging.info("--- Script Session Started ---")
    
    try:
        with open('secret.key', 'rb') as key_file:
            key = key_file.read()
        cipher_suite = Fernet(key)
        logging.info("Encryption key loaded successfully.")
    except FileNotFoundError:
        logging.critical("Encryption key ('secret.key') not found. Please run generate_key.py first.")
        return

    ip_list = []
    if args.ip:
        ip_list.append(args.ip)
        logging.info(f"Received single IP to check: {args.ip}")
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                ip_list = [line.strip() for line in f if line.strip()]
            logging.info(f"Loaded {len(ip_list)} IPs from '{args.file}'.")
        except FileNotFoundError:
            logging.error(f"Input file not found: {args.file}. Aborting.")
            return
    else:
        print(" No input provided. Use -i for a single IP or -f for a file. Use -h for help.")
        return

    output_filename = 'ip_reputation_results.csv.enc'
    csv_header = ["IP Address", "Malicious Detections", "Owner", "Hostname"]
    
    try:
        string_buffer = io.StringIO()
        writer = csv.writer(string_buffer)
        writer.writerow(csv_header)
        
        logging.info(f"Processing IPs and preparing encrypted report...")
        
        for ip in ip_list:
            if not ip: continue

            # PRIVACY SAFEGUARD
            if is_private_ip(ip):
                logging.warning(f"Skipping private/internal IP address: {ip}")
                writer.writerow([ip, "N/A", "Private IP", "N/A"])
                continue

            logging.info(f"--- Processing IP: {ip} ---")
            
            malicious_count = check_ip_reputation(ip)
            owner = get_whois_info(ip)
            hostname = get_hostname(ip)
            
            data_row = [ip, malicious_count, owner, hostname]
            writer.writerow(data_row)
            
            logging.info(f"Successfully processed data for {ip}.")
            
            if len(ip_list) > 1:
                time.sleep(16)

        csv_data_string = string_buffer.getvalue()
        encrypted_data = cipher_suite.encrypt(csv_data_string.encode('utf-8'))
        
        with open(output_filename, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
        logging.info(f"Encrypted results saved to '{output_filename}'.")

        readable_hash = hashlib.sha256(encrypted_data).hexdigest()
        hash_filename = output_filename + '.sha256'
        with open(hash_filename, 'w') as hf:
            hf.write(readable_hash)
        logging.info(f"Hash saved to '{hash_filename}'.")
        print(f" Report created. Hash: {readable_hash}")

    except Exception as e:
        logging.critical(f"An unexpected critical error occurred: {e}", exc_info=True)
    
    logging.info("--- Script Session Finished ---")

if __name__ == "__main__":
    main()