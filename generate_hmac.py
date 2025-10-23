# generate_hmac.py
import hmac, hashlib

# Use the same key as in app.py
HMAC_KEY = b"change_this_secret_key"   # ⚠️ You can replace this with your own secret key

MODEL_PATH = "model.pkl"
SIG_PATH = "model.pkl.hmac"

with open(MODEL_PATH, "rb") as f:
    model_data = f.read()

# Create HMAC signature
signature = hmac.new(HMAC_KEY, model_data, hashlib.sha256).hexdigest()

# Save it to file
with open(SIG_PATH, "w") as sig_file:
    sig_file.write(signature)

print(f"✅ HMAC signature created and saved to {SIG_PATH}")
