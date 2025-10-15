# decrypt_report.py
from cryptography.fernet import Fernet
import sys

# --- DEFINE FILE NAMES ---
encrypted_file = 'ip_reputation_results.csv.enc'
decrypted_file = 'decrypted_report.csv' # The new output file name

# --- LOAD THE KEY ---
try:
    with open('secret.key', 'rb') as key_file:
        key = key_file.read()
    cipher_suite = Fernet(key)
except FileNotFoundError:
    print(" ERROR: 'secret.key' not found. Make sure it's in the same folder.")
    sys.exit(1)

# --- DECRYPT THE FILE AND SAVE IT ---
try:
    # Read the encrypted file
    with open(encrypted_file, 'rb') as file_to_decrypt:
        encrypted_data = file_to_decrypt.read()
    
    # Decrypt the data
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    
    # Save the decrypted data to a new CSV file
    with open(decrypted_file, 'wb') as output_csv:
        output_csv.write(decrypted_data)
        
    print(f" Success! Report decrypted and saved as '{decrypted_file}'")

except FileNotFoundError:
    print(f" ERROR: Encrypted file '{encrypted_file}' not found.")
except Exception as e:
    print(f" An error occurred during decryption (wrong key?): {e}")