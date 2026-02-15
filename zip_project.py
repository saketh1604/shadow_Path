import zipfile
import os

files_to_zip = [
    'obfuscator.py',
    'verify_integrity.py',
    'mock_anchor.html',
    'shadow_bookmarklet.js',
    '.gitignore',
    'requirements.txt',
    'README.md'
]

output_zip = 'Shadow-Path-Project.zip'

with zipfile.ZipFile(output_zip, 'w') as zipf:
    for file in files_to_zip:
        if os.path.exists(file):
            zipf.write(file)
            print(f"Added {file}")
        else:
            print(f"Warning: {file} not found")

print(f"Created {output_zip}")
