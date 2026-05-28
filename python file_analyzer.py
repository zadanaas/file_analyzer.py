import os
import hashlib
import mimetypes
import datetime
import json

def calculate_hashes(file_path):
    """Calculate MD5 and SHA256 hashes for a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except Exception as e:
        return None, None

def analyze_file(file_path):
    """Collect metadata and hashes for a single file."""
    stats = os.stat(file_path)
    size = stats.st_size
    modified = datetime.datetime.fromtimestamp(stats.st_mtime)
    mime_type, _ = mimetypes.guess_type(file_path)
    md5, sha256 = calculate_hashes(file_path)

    # Simple suspicious check (educational only)
    suspicious = False
    if mime_type and "exe" in mime_type:
        suspicious = True
    if file_path.endswith((".vbs", ".bat", ".ps1", ".js")):
        suspicious = True

    return {
        "file": file_path,
        "size_bytes": size,
        "last_modified": str(modified),
        "type": mime_type or "Unknown",
        "md5": md5,
        "sha256": sha256,
        "suspicious": suspicious
    }

def analyze_directory(directory):
    """Analyze all files in a directory."""
    results = []
    for root, _, files in os.walk(directory):
        for name in files:
            file_path = os.path.join(root, name)
            results.append(analyze_file(file_path))
    return results

if __name__ == "__main__":
    folder = input("Enter folder path to analyze: ")
    report = analyze_directory(folder)
    print(json.dumps(report, indent=4))

