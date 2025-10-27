# generate_hmac.py
"""
Generate an HMAC-SHA256 signature for model.pkl and save it to model.pkl.hmac.

Usage:
  1) Set MODEL_HMAC_KEY in your environment (recommended).
     - Windows (PowerShell):
         $env:MODEL_HMAC_KEY = "your_super_secret_key"
     - Linux/macOS:
         export MODEL_HMAC_KEY="your_super_secret_key"

  2) Run:
       python generate_hmac.py

This writes model.pkl.hmac containing the hex HMAC string.
Keep MODEL_HMAC_KEY secret (do NOT commit it to source control).
"""

import os
import hmac
import hashlib
import sys

MODEL_PATH = "model.pkl"
SIG_PATH = "model.pkl.hmac"

def get_key():
    key = os.environ.get("MODEL_HMAC_KEY")
    if key:
        return key.encode("utf-8")
    # fallback - change this before use in production
    return b"change_this_secret_key"

def main():
    if not os.path.exists(MODEL_PATH):
        print(f"Error: {MODEL_PATH} not found in current directory.")
        sys.exit(1)

    key = get_key()
    try:
        with open(MODEL_PATH, "rb") as f:
            data = f.read()
    except Exception as e:
        print("Failed to read model file:", e)
        sys.exit(1)

    sig = hmac.new(key, data, hashlib.sha256).hexdigest()

    try:
        with open(SIG_PATH, "w", encoding="utf-8") as s:
            s.write(sig)
    except Exception as e:
        print("Failed to write signature file:", e)
        sys.exit(1)

    print(f"✅ Signature written to {SIG_PATH}")
    print(f"HMAC (first 16 chars): {sig[:16]}...")

if __name__ == "__main__":
    main()
