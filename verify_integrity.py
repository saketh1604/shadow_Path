import re
import base64
import hashlib
import hmac
import struct
import sys

# Verification Script mimicking the JS Decryption Logic

def derive_keys(trigger_text):
    master_key = hashlib.sha256(trigger_text.encode('utf-8')).digest()
    enc_key = hmac.new(master_key, b"ENC", hashlib.sha256).digest()
    mac_key = hmac.new(master_key, b"MAC", hashlib.sha256).digest()
    return enc_key, mac_key

def decrypt_blob(blob_b64, trigger_text):
    try:
        combined_data = base64.b64decode(blob_b64)
        nonce = combined_data[:16]
        tag = combined_data[16:48]
        ciphertext = combined_data[48:]

        enc_key, mac_key = derive_keys(trigger_text)

        # 1. Verify MAC
        calc_tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, calc_tag):
            print("[-] INTEGRITY FAILURE: MAC mismatch. The trigger text might be wrong.")
            return False

        # 2. Decrypt (CTR)
        plaintext = bytearray()
        num_blocks = (len(ciphertext) + 31) // 32
        for i in range(num_blocks):
            counter_block = nonce + struct.pack(">I", i)
            keystream = hmac.new(enc_key, counter_block, hashlib.sha256).digest()
            
            chunk = ciphertext[i*32 : (i+1)*32]
            for j in range(len(chunk)):
                plaintext.append(chunk[j] ^ keystream[j])

        return plaintext.decode('utf-8')

    except Exception as e:
        print(f"[-] ERROR: {e}")
        return False

def main():
    print("[*] Starting Shadow-Path Integrity Check...")
    
    # 1. Read the generated bookmarklet
    try:
        with open("shadow_bookmarklet.js", "r", encoding="utf-8") as f:
            js_content = f.read()
    except FileNotFoundError:
        print("[-] Error: shadow_bookmarklet.js not found. Run obfuscator.py first.")
        sys.exit(1)

    # 2. Extract Blob using Regex
    blob_match = re.search(r'encryptedBlob:\s*"([^"]+)"', js_content)
    if not blob_match:
        print("[-] Error: Could not find encryptedBlob in JS file.")
        sys.exit(1)
    
    blob = blob_match.group(1)
    print(f"[+] Found Encrypted Blob: {blob[:20]}...")

    # 3. Define the Trigger (Must match what was used in generation)
    # In a real test we'd parse this too or pass it in, but for verification we use the known test case.
    trigger_text = "The pixel density is exactly what I needed for my workflow. Highly recommended."
    print(f"[*] Attempting decryption with Trigger: '{trigger_text[:30]}...'")

    # 4. Decrypt
    result = decrypt_blob(blob, trigger_text)

    if result:
        print(f"[+] SUCCESS: Decrypted URL -> {result}")
        if "google.com" in result: # The test case target
            print("[+] VERIFICATION PASSED: Payload redirects to expected target.")
        else:
            print("[?] WARNING: Decrypted, but unexpected target.")
    else:
        print("[-] VERIFICATION FAILED.")
        sys.exit(1)

if __name__ == "__main__":
    main()
