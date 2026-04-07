from classifier import classify_file

file_path = input("Enter file path to classify: ")

result = classify_file(file_path)

print("\nPredicted Category:", result)