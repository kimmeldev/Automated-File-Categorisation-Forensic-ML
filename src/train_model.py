import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

from feature_extractor import extract_features

dataset_path = "../dataset"

data = []
labels = []

for category in os.listdir(dataset_path):

    category_path = os.path.join(dataset_path, category)

    if not os.path.isdir(category_path):
        continue

    for file in os.listdir(category_path):

        file_path = os.path.join(category_path, file)

        features = extract_features(file_path)

        if features:

            data.append([
                features["size"],
                features["extension"],
                features["mime"],
                features["signature"]
            ])

            labels.append(category)

df = pd.DataFrame(data, columns=["size", "extension", "mime", "signature"])

# encoders
ext_encoder = LabelEncoder()
mime_encoder = LabelEncoder()
sig_encoder = LabelEncoder()

df["extension"] = ext_encoder.fit_transform(df["extension"])
df["mime"] = mime_encoder.fit_transform(df["mime"])
df["signature"] = sig_encoder.fit_transform(df["signature"])

model = RandomForestClassifier(n_estimators=100)

model.fit(df, labels)

# save model + encoders
joblib.dump(model, "../model/file_classifier.pkl")
joblib.dump(ext_encoder, "../model/ext_encoder.pkl")
joblib.dump(mime_encoder, "../model/mime_encoder.pkl")
joblib.dump(sig_encoder, "../model/sig_encoder.pkl")

print("Model trained successfully!")