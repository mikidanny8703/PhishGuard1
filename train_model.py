# train_model.py
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from phishing_features import extract_features

# === Load dataset ===
df = pd.read_csv("train_80.csv")  # your dataset file
print(f"Dataset loaded. Shape: {df.shape}")

# Detect URL and label column
url_col = "URL"
label_col = "label"

# Convert label if necessary
df[label_col] = df[label_col].replace({"benign": 0, "legitimate": 0, "phishing": 1}).astype(int)

# === Extract features ===
features_list = []
for url in df[url_col]:
    features_list.append(extract_features(url)[0])  # flatten to list

X = pd.DataFrame(features_list)
y = df[label_col]

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=120, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"✅ Model accuracy: {acc:.2f}")

# Save model
joblib.dump(model, "model.pkl")
print("Model saved as model.pkl")
