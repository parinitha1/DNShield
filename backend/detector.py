import joblib
from backend.features import extract_features
from backend.config import MODEL_PATH

model = joblib.load(MODEL_PATH)

def classify(domain):
    features = extract_features(domain)
    
    prediction = model.predict([[features["length"], features["entropy"]]])
    
    if prediction[0] == -1:
        return "Malicious"
    return "Normal"