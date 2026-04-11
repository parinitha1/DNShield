import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

# ✅ Step 1: Create proper path to save model
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # current folder (models/)
model_path = os.path.join(BASE_DIR, "dns_model.pkl")

# ✅ Step 2: Dummy training data (you can improve later)
data = pd.DataFrame({
    "length": [10, 15, 20, 25, 30, 80, 90, 100, 110],
    "entropy": [2.1, 2.5, 2.7, 2.9, 3.0, 4.5, 4.8, 5.2, 5.5]
})

# ✅ Step 3: Train model
model = IsolationForest(contamination=0.3, random_state=42)
model.fit(data)

# ✅ Step 4: Save model safely
joblib.dump(model, model_path)

print(f"Model trained and saved at: {model_path}")