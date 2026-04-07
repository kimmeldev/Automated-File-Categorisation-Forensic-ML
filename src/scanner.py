import os
import pandas as pd
from feature_extractor import extract_features

def scan_folder(folder_path):

    results = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:

            file_path = os.path.join(root, file)

            features = extract_features(file_path)

            if features:
                features["filename"] = file
                features["path"] = file_path

                results.append(features)

    df = pd.DataFrame(results)

    return df


if __name__ == "__main__":

    folder = input("Enter folder path to scan: ")

    data = scan_folder(folder)

    print("\nScan Results:")
    print(data)