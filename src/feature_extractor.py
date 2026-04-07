import os
import hashlib
import magic
import math
import datetime


def get_file_hash(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()


def get_file_signature(file_path):

    with open(file_path, "rb") as f:
        header = f.read(4)

    hex_header = header.hex().upper()

    if hex_header.startswith("4D5A"):
        return "exe"
    elif hex_header.startswith("FFD8FF"):
        return "jpg"
    elif hex_header.startswith("89504E47"):
        return "png"
    elif hex_header.startswith("25504446"):
        return "pdf"
    else:
        return "unknown"


def calculate_entropy(file_path):

    with open(file_path, "rb") as f:
        data = f.read()

    if not data:
        return 0

    byte_counts = [0] * 256

    for b in data:
        byte_counts[b] += 1

    entropy = 0
    data_len = len(data)

    for count in byte_counts:

        if count == 0:
            continue

        p = count / data_len
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def get_file_timestamps(file_path):

    created = os.path.getctime(file_path)
    modified = os.path.getmtime(file_path)
    accessed = os.path.getatime(file_path)

    created_time = datetime.datetime.fromtimestamp(created)
    modified_time = datetime.datetime.fromtimestamp(modified)
    accessed_time = datetime.datetime.fromtimestamp(accessed)

    return created_time, modified_time, accessed_time


def extract_features(file_path):

    size = os.path.getsize(file_path)
    extension = os.path.splitext(file_path)[1].lower()

    try:
        mime = magic.from_file(file_path, mime=True)
    except:
        mime = "unknown"

    signature = get_file_signature(file_path)

    try:
        file_hash = get_file_hash(file_path)
    except:
        file_hash = "unknown"

    entropy = calculate_entropy(file_path)

    created_time, modified_time, accessed_time = get_file_timestamps(file_path)

    return {
        "size": size,
        "extension": extension,
        "mime": mime,
        "signature": signature,
        "hash": file_hash,
        "entropy": entropy,
        "created_time": created_time,
        "modified_time": modified_time,
        "accessed_time": accessed_time
    }