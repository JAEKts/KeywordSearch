import os
import re
import json
import mimetypes
import hcl2  # Install via: pip install python-hcl2
import yaml  # Install via: pip install pyyaml
import argparse

# Secret patterns to search for
SECRET_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS Access Key
    re.compile(r'aws_secret_access_key=[A-Za-z0-9/+=]{40}'),  # AWS Secret Key
    re.compile(r'arn:aws:iam::[0-9]{12}:role/[a-zA-Z0-9_-]+'),  # AWS IAM Role
    re.compile(r'ASIA[0-9A-Z]{16}'),  # AWS Temporary Access Key
    re.compile(r'secret-[a-zA-Z0-9_-]+'),  # AWS Secrets Manager secret
    re.compile(r'(?i)(password|secret|key|token|aws_access_key_id|aws_secret_access_key)[=: ]+.{8,}')  # Generic patterns
]

# File extensions to scan
FILE_EXTENSIONS = [
    '.py', '.js', '.json', '.yaml', '.yml', '.tf', '.tfstate', '.env', '.ini', '.properties', 
    '.java', '.go', '.rb', '.ts', '.html', '.sh', 'Dockerfile', '.helm', '.smithy'  # Added .smithy support
]

# Function to detect binary files
def is_binary(file_path):
    mime = mimetypes.guess_type(file_path)[0]
    return mime and (mime.startswith('application/octet-stream') or mime.startswith('application/x-binary'))

# Search for secrets in plain text files
def search_plain_text_file(file_path):
    matches = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_number, line in enumerate(f, start=1):
                for pattern in SECRET_PATTERNS:
                    for match in pattern.findall(line):
                        matches.append((file_path, line_number, match))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return matches

# Search for secrets in JSON files
def search_json_file(file_path):
    matches = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            matches.extend(recursive_json_search(data, file_path))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return matches

def recursive_json_search(data, file_path, parent_key=''):
    matches = []
    if isinstance(data, dict):
        for key, value in data.items():
            matches.extend(recursive_json_search(value, file_path, parent_key=key))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            matches.extend(recursive_json_search(item, file_path, parent_key=f"{parent_key}[{index}]"))
    else:
        for pattern in SECRET_PATTERNS:
            if pattern.search(str(data)):
                matches.append((file_path, parent_key, data))
    return matches

# Search for secrets in YAML files
def search_yaml_file(file_path):
    matches = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            matches.extend(recursive_json_search(data, file_path))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return matches

# Search for secrets in Terraform (.tf) files
def search_terraform_file(file_path):
    matches = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = hcl2.load(f)
            matches.extend(recursive_json_search(data, file_path))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return matches

# Search for secrets in Dockerfiles
def search_dockerfile(file_path):
    matches = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_number, line in enumerate(f, start=1):
                if line.startswith('ENV') or 'RUN' in line:
                    for pattern in SECRET_PATTERNS:
                        for match in pattern.findall(line):
                            matches.append((file_path, line_number, match))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return matches

# Search for secrets in Smithy files
def search_smithy_file(file_path):
    matches = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_number, line in enumerate(f, start=1):
                for pattern in SECRET_PATTERNS:
                    for match in pattern.findall(line):
                        matches.append((file_path, line_number, match))
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return matches

# Main function to determine the file type and handle accordingly
def search_file_for_secrets(file_path):
    if is_binary(file_path):
        print(f"Skipping binary file: {file_path}")
        return []

    if file_path.endswith('.json'):
        return search_json_file(file_path)
    elif file_path.endswith(('.yaml', '.yml')):
        return search_yaml_file(file_path)
    elif file_path.endswith('.tf'):
        return search_terraform_file(file_path)
    elif 'Dockerfile' in file_path:
        return search_dockerfile(file_path)
    elif file_path.endswith('.smithy'):
        return search_smithy_file(file_path)  # Check for .smithy files
    else:
        return search_plain_text_file(file_path)

# Recursively search for files in directories
def search_directory_for_secrets(directory):
    all_matches = []
    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if any(file_path.endswith(ext) for ext in FILE_EXTENSIONS) or 'Dockerfile' in file_name:
                matches = search_file_for_secrets(file_path)
                all_matches.extend(matches)
    return all_matches

# Sample usage with argparse for directory input
def main():
    parser = argparse.ArgumentParser(description="Search for secrets in code files.")
    parser.add_argument(
        "-d", "--directory", 
        help="Directory to search for secrets (default: current working directory)", 
        default=os.getcwd()
    )
    
    args = parser.parse_args()
    directory_to_search = args.directory
    
    results = search_directory_for_secrets(directory_to_search)
    
    # Example: Output results
    for match in results:
        print(f"Secret found in {match[0]} on line {match[1]}: {match[2]}")

if __name__ == '__main__':
    main()
