
(function() {
    console.log("[Shadow-Path] Listener Active.");

    const CONFIG = {
        triggerSelector: ".shadow-trigger .comment-body", 
        encryptedBlob: "j/CGnv1tTIw3isrCOyylvgordtIW8AAz5WBV9e4kgoQVkeZ1B2Vf/W/P78mXon/hK0r+529pEexmFSxWj575j+6a1klAxV6bWbUZog==" 
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
