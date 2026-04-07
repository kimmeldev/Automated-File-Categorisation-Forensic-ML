import os
import joblib
import pandas as pd
from feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, "model", "file_classifier.pkl")
EXT_ENCODER_PATH = os.path.join(BASE_DIR, "model", "ext_encoder.pkl")
MIME_ENCODER_PATH = os.path.join(BASE_DIR, "model", "mime_encoder.pkl")
SIG_ENCODER_PATH = os.path.join(BASE_DIR, "model", "sig_encoder.pkl")

model = joblib.load(MODEL_PATH)
ext_encoder = joblib.load(EXT_ENCODER_PATH)
mime_encoder = joblib.load(MIME_ENCODER_PATH)
sig_encoder = joblib.load(SIG_ENCODER_PATH)


def classify_file(file_path):

    features = extract_features(file_path)

    if not features:
        return "unknown", 0

    try:
        ext = ext_encoder.transform([features["extension"]])[0]
    except:
        ext = -1

    try:
        mime = mime_encoder.transform([features["mime"]])[0]
    except:
        mime = -1

    try:
        sig = sig_encoder.transform([features["signature"]])[0]
    except:
        sig = -1

    df = pd.DataFrame([[
        features["size"],
        ext,
        mime,
        sig
    ]], columns=["size", "extension", "mime", "signature"])

    prediction = model.predict(df)[0]

    # get probability
    probabilities = model.predict_proba(df)[0]
    confidence = max(probabilities) * 100

    return prediction, round(confidence, 2)