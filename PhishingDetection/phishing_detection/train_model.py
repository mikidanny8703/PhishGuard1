import pandas as pd
import numpy as np
import joblib, hmac, hashlib, os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from phishing_features import extract_features

DATA_CSV = "train_80.csv"
MODEL_PATH = "model.pkl"
SIG_PATH = "model.pkl.hmac"
HMAC_KEY = os.environ.get("MODEL_HMAC_KEY", "change_this_secret_key").encode("utf-8")

df = pd.read_csv(DATA_CSV)
url_col, label_col = "URL", "label"

if df[label_col].dtype == object:
    df[label_col] = df[label_col].replace({"benign":0, "legitimate":0, "phishing":1})
y = df[label_col].astype(int)

X = np.vstack([extract_features(u) for u in df[url_col]])
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

joblib.dump(model, MODEL_PATH)
with open(MODEL_PATH, "rb") as f:
    sig = hmac.new(HMAC_KEY, f.read(), hashlib.sha256).hexdigest()
with open(SIG_PATH, "w") as f:
    f.write(sig)

print("✅ Model + HMAC signature saved.")
