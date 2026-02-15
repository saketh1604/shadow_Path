# Project Shadow-Path: Verification Walkthrough

> [!TIP]
> **Verification Status**: SUCCESS.
> The manual verification steps below have been confirmed to work (User Verified).

## Prerequisites
- Python 3.x installed
- Use the `shadow-path` directory in your scratchpad: `C:\Users\pakan\.gemini\antigravity\scratch\shadow-path`

## 1. Generate the Shadow Payload
We have already generated a sample payload targeting the mock anchor site. If you want to regenerate it:

```powershell
python obfuscator.py --url "https://news.ycombinator.com" --trigger "The pixel density is exactly what I needed for my workflow. Highly recommended." --selector ".shadow-trigger .comment-body"
```

This creates `shadow_bookmarklet.js`.

## 2. Prepare the Anchor Site
Open the `mock_anchor.html` file in your browser:
**Path**: `C:\Users\pakan\.gemini\antigravity\scratch\shadow-path\mock_anchor.html`

## 3. Inject the Listener (The "Bookmarklet")
1. Open Browser Developer Tools (**F12** or **Ctrl+Shift+I**).
2. Go to the **Console** tab.
3. Copy the entire content of `shadow_bookmarklet.js`.
4. Paste it into the Console and press **Enter**.
5. You should see an alert: *"Shadow-Path Listener Injected..."*

## 4. Trigger the Redirect
1. On the web page, locate the comment by **Saketh R.** (Time: 5 hours ago).
2. The text is: *"The pixel density is exactly what I needed for my workflow. Highly recommended."*
3. **Click** on that text.

## 5. Verify Success
- **Expected Behavior**: 
    - You will see an alert: *"Redirecting to secret location..."*
    - The browser will redirect to `https://news.ycombinator.com`.
- **Failure Condition**: 
    - If you click other comments, nothing happens.
    - If the crypto fails, an alert *"Shadow-Path: Access Denied"* will appear.

## Technical Notes
- **Zero-Dependency Crypto**: The implementation uses a custom Python-to-JS bridge. Python uses `hmac` + `hashlib` to implement a `CTR` stream cipher. JavaScript uses the standard `Web Crypto API` to decrypt it.
- **Steganography**: The decryption key is derived *only* from the text content of the trigger element. If the text changes even by one character, decryption will fail.


