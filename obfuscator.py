import argparse
import base64
import hashlib
import hmac
import os
import sys
import struct

# --- Standard Library Crypto Implementation ---
# Since 'cryptography' library is not available in this environment, 
# we implement a robust Encrypt-then-MAC scheme using HMAC-SHA256 in CTR mode.
# This ensures zero dependencies while maintaining decent security for a prototype.

def derive_keys(trigger_text):
    """Derives encryption and MAC keys from the trigger text."""
    # Use SHA-256 to get a master key
    master_key = hashlib.sha256(trigger_text.encode('utf-8')).digest()
    # Split into Enc Key and Mac Key using HKDF-like approach or just different contexts
    enc_key = hmac.new(master_key, b"ENC", hashlib.sha256).digest()
    mac_key = hmac.new(master_key, b"MAC", hashlib.sha256).digest()
    return enc_key, mac_key

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(plaintext, trigger_text):
    """Encrypts plaintext using a custom CTR mode with HMAC-SHA256."""
    enc_key, mac_key = derive_keys(trigger_text)
    nonce = os.urandom(16)
    
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = bytearray()
    
    # CTR Mode
    num_blocks = (len(plaintext_bytes) + 31) // 32
    for i in range(num_blocks):
        # Counter block: Nonce + Counter(4 bytes)
        counter_block = nonce + struct.pack(">I", i)
        # Generate hash of counter block to use as keystream
        keystream = hmac.new(enc_key, counter_block, hashlib.sha256).digest()
        
        # XOR with plaintext chunk
        chunk = plaintext_bytes[i*32 : (i+1)*32]
        ciphertext.extend(xor_bytes(chunk, keystream[:len(chunk)]))
    
    ciphertext = bytes(ciphertext)
    
    # Calculate MAC (HMAC-SHA256 of Nonce + Ciphertext)
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    
    # Output: Nonce + Tag + Ciphertext
    return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

# --- The JavaScript Listener Template (Pure JS Crypto) ---
# Implements the decryption counterpart using Web Crypto API or pure JS if needed.
# Since we used standard HMAC-SHA256, we can use Web Crypto API for SHA-256 and HMAC.
JS_TEMPLATE = """
(function() {
    console.log("[Shadow-Path] Listener Active.");

    const CONFIG = {
        triggerSelector: "{{TRIGGER_SELECTOR}}", 
        encryptedBlob: "{{ENCRYPTED_BLOB}}" 
    };

    function base64ToArrayBuffer(base64) {
        var binary_string = window.atob(base64);
        var len = binary_string.length;
        var bytes = new Uint8Array(len);
        for (var i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes; // Return Uint8Array directly
    }

    async function decryptAndRedirect(triggerText) {
        try {
            console.log("[Shadow-Path] Decrypting...");
            
            // 1. Derive Keys
            const encoder = new TextEncoder();
            const masterKeyMaterial = await window.crypto.subtle.digest("SHA-256", encoder.encode(triggerText));
            const masterKey = await window.crypto.subtle.importKey("raw", masterKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
            
            const encKeyMaterial = await window.crypto.subtle.sign("HMAC", masterKey, encoder.encode("ENC"));
            const macKeyMaterial = await window.crypto.subtle.sign("HMAC", masterKey, encoder.encode("MAC"));
            
            const encKey = await window.crypto.subtle.importKey("raw", encKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
            const macKey = await window.crypto.subtle.importKey("raw", macKeyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);

            // 2. Parse Blob
            const combinedData = base64ToArrayBuffer(CONFIG.encryptedBlob);
            const nonce = combinedData.slice(0, 16);
            const tag = combinedData.slice(16, 48); // SHA256 is 32 bytes
            const ciphertext = combinedData.slice(48);

            // 3. Verify MAC
            // Ensure data integrity before decrypting
            const dataToVerify = new Uint8Array(nonce.length + ciphertext.length);
            dataToVerify.set(nonce);
            dataToVerify.set(ciphertext, nonce.length);
            
            const isValid = await window.crypto.subtle.verify("HMAC", macKey, tag, dataToVerify);
            if (!isValid) {
                throw new Error("Integrity check failed. Wrong trigger text?");
            }

            // 4. Decrypt (CTR Mode)
            let plaintextBytes = new Uint8Array(ciphertext.length);
            const numBlocks = Math.ceil(ciphertext.length / 32);
            
            for (let i = 0; i < numBlocks; i++) {
                // Construct counter block: Nonce + Counter(4 bytes big endian)
                const counterBlock = new Uint8Array(16 + 4);
                counterBlock.set(nonce);
                const view = new DataView(counterBlock.buffer);
                view.setUint32(16, i, false); // Big Endian

                // Generate Keystream
                const keystream = await window.crypto.subtle.sign("HMAC", encKey, counterBlock);
                const keystreamBytes = new Uint8Array(keystream);

                // XOR
                const start = i * 32;
                const end = Math.min(start + 32, ciphertext.length);
                for (let j = start; j < end; j++) {
                    plaintextBytes[j] = ciphertext[j] ^ keystreamBytes[j - start];
                }
            }

            const decryptedUrl = new TextDecoder().decode(plaintextBytes);
            console.log("[Shadow-Path] Success! Redirecting to: " + decryptedUrl);
            alert("Redirecting to secret location...");
            window.location.href = decryptedUrl;

        } catch (e) {
            console.error("[Shadow-Path] Decryption Failed.", e);
            alert("Shadow-Path: Access Denied. " + e.message);
        }
    }

    document.addEventListener("click", function(e) {
        const target = e.target.closest(CONFIG.triggerSelector);
        if (target) {
            e.preventDefault();
            e.stopPropagation();
            decryptAndRedirect(target.innerText.trim());
        }
    });

    alert("Shadow-Path Listener Injected. Click the target to activate.");
})();
"""

def main():
    parser = argparse.ArgumentParser(description="Shadow-Path: Steganographic redirection tool (Pure Python).")
    parser.add_argument("--url", required=True, help="The destination URL.")
    parser.add_argument("--trigger", required=True, help="The exact text of the trigger element.")
    parser.add_argument("--selector", default=".shadow-trigger", help="CSS selector.")
    
    args = parser.parse_args()

    print(f"[*] Baking Shadow-Path Payload (Zero-Dependency Mode)...")
    print(f"    Target: {args.url}")
    
    blob = encrypt(args.url, args.trigger)
    print(f"[*] Encrypted Blob: {blob[:20]}...")

    js_code = JS_TEMPLATE.replace("{{TRIGGER_SELECTOR}}", args.selector) \
                         .replace("{{ENCRYPTED_BLOB}}", blob)

    output_filename = "shadow_bookmarklet.js"
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(js_code)
    
    print(f"[*] Listener script saved to: {output_filename}")

if __name__ == "__main__":
    main()
