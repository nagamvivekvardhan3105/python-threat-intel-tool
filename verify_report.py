# verify_report.py
import hashlib
import sys

# --- DEFINE FILE NAMES ---
# You can make this take command-line arguments for more flexibility
report_file = 'ip_reputation_results.csv.enc'
hash_file = 'ip_reputation_results.csv.enc.sha256'

try:
    # --- 1. Read the original, trusted hash ---
    with open(hash_file, 'r') as hf:
        original_hash = hf.read().strip()

    # --- 2. Calculate the hash of the current report file ---
    with open(report_file, 'rb') as rf:
        bytes = rf.read()
        current_hash = hashlib.sha256(bytes).hexdigest()

    # --- 3. Compare the hashes ---
    print(f"Original hash:  {original_hash}")
    print(f"Current hash:   {current_hash}")

    if original_hash == current_hash:
        print("\n SUCCESS: The report is authentic and has not been tampered with.")
    else:
        print("\n WARNING: The report has been altered! The hash does not match.")

except FileNotFoundError:
    print(f"ERROR: Make sure both '{report_file}' and '{hash_file}' are in this folder.")
except Exception as e:
    print(f" An error occurred: {e}")