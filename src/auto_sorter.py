import os
import shutil
import csv

from classifier import classify_file
from feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import sys

case_id = sys.argv[1]

CASE_FOLDER = os.path.join(BASE_DIR, "cases", case_id)

INPUT_FOLDER = os.path.join(CASE_FOLDER, "uploads")
OUTPUT_FOLDER = os.path.join(CASE_FOLDER, "processed")
REPORT_FILE = os.path.join(CASE_FOLDER, "analysis_report.csv")


def calculate_risk_score(suspicious, entropy, confidence, category):

    score = 0

    if suspicious:
        score += 70

    if category == "executables" and entropy > 7:
        score += 20

    if confidence < 60:
        score += 10

    return score


def sort_files():

    report_rows = []
    suspicious_files = []
    risk_table = []

    total_files = 0
    image_count = 0
    doc_count = 0
    video_count = 0
    exe_count = 0
    suspicious_count = 0

    for file in os.listdir(INPUT_FOLDER):

        file_path = os.path.join(INPUT_FOLDER, file)

        if os.path.isfile(file_path):

            total_files += 1

            category, confidence = classify_file(file_path)

            features = extract_features(file_path)

            extension = features["extension"].replace(".", "")
            signature = features["signature"]
            sha256 = features["hash"]
            entropy = features["entropy"]

            created_time = features["created_time"]
            modified_time = features["modified_time"]
            accessed_time = features["accessed_time"]

            suspicious = False

            if signature != "unknown" and extension != signature:
                suspicious = True
                suspicious_files.append(file)
                suspicious_count += 1

            risk_score = calculate_risk_score(
                suspicious, entropy, confidence, category
            )

            risk_table.append((file, risk_score))

            if category == "images":
                image_count += 1
            elif category == "documents":
                doc_count += 1
            elif category == "videos":
                video_count += 1
            elif category == "executables":
                exe_count += 1

            category_folder = os.path.join(OUTPUT_FOLDER, category)
            os.makedirs(category_folder, exist_ok=True)

            destination = os.path.join(category_folder, file)

            shutil.copy(file_path, destination)

            status = "SUSPICIOUS" if suspicious else "NORMAL"

            indicators = []

            if suspicious:
                indicators.append("Extension Mismatch")

            if category == "executables" and entropy > 7:
                indicators.append("High Entropy")

            if confidence < 60:
                indicators.append("Low Confidence")
            indicator_text = ", ".join(indicators) if indicators else "-"

            print(f"{file} → {category} ({confidence}%) | Indicators: {indicator_text}")

            print(f"   Created: {created_time}")
            print(f"   Modified: {modified_time}")
            print(f"   Accessed: {accessed_time}")

            # Format timestamps
            created_time = created_time.strftime("%Y-%m-%d %H:%M:%S")
            modified_time = modified_time.strftime("%Y-%m-%d %H:%M:%S")
            accessed_time = accessed_time.strftime("%Y-%m-%d %H:%M:%S")

            report_rows.append([
                file,
                extension,
                signature,
                category,
                confidence,
                status,
                entropy,
                created_time,
                modified_time,
                accessed_time,
                sha256,
                risk_score,
                indicator_text
            ])

    with open(REPORT_FILE, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "filename",
            "extension",
            "signature",
            "prediction",
            "confidence",
            "status",
            "entropy",
            "created_time",
            "modified_time",
            "accessed_time",
            "sha256",
            "risk_score",
            "indicators"
        ])

        writer.writerows(report_rows)

    print("\nForensic report generated:", REPORT_FILE)

    print("\nScan Summary")
    print("------------")
    print("Total files scanned:", total_files)
    print("Images:", image_count)
    print("Documents:", doc_count)
    print("Videos:", video_count)
    print("Executables:", exe_count)
    print("Suspicious files:", suspicious_count)

    if suspicious_files:

        print("\nSuspicious Files")
        print("----------------")

        for f in suspicious_files:
            print(f)

    risk_table.sort(key=lambda x: x[1], reverse=True)

    print("\nEvidence Risk Ranking")
    print("---------------------")

    for file, score in risk_table:

        if score >= 70:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        print(f"{file} → Risk Score: {score} ({level})")


if __name__ == "__main__":
    sort_files()