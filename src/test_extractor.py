from feature_extractor import extract_features

file_path = input("Enter file path: ")

features = extract_features(file_path)

print("\nExtracted Features:")
print(features)