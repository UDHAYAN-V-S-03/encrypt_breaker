# Encrypt Breaker

**Encrypt Breaker — Multi-tool Password and Encryption Analyzer**

> A compact, command-line Python utility that bundles hash analysis, dictionary attacks against password-protected files, and Windows system-level encryption diagnostics into a single interactive tool.

---

## 🛡️ Overview

Encrypt Breaker is an interactive CLI tool (Python) that provides a consolidated set of utilities for:

* Generating cryptographic hashes from plaintext
* Performing dictionary-based cracking of single hashes or lists of hashes
* Attempting dictionary attacks against password‑protected archive and document formats
* Scanning folders for protected files
* Checking BitLocker status and recovery key info on Windows

This project is designed to be a single utility that removes the need to jump between several separate tools for common password/encryption analysis tasks.

## ✨ Key Features

| Menu Option                           | Functionality                                                                                      | Supported Algorithms / Formats              |
| ------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| Hash Generation                       | Convert plaintext strings into cryptographic hash values                                           | `MD5`, `SHA1`, `SHA256`, `SHA512`           |
| Hash Cracking                         | Dictionary attack against a single hash or a file of hashes                                        | `MD5`, `SHA1`, `SHA256`, `SHA512`           |
| File Decryption                       | Dictionary attack to discover the password for protected archives/documents                        | `ZIP`, `RAR`, `PDF`, `DOCX`, `PPTX`, `XLSX` |
| Protected File Scan                   | Recursively scan folders (or the entire system) to find password-protected files                   | `ZIP`, `RAR`, `PDF`, Microsoft Office files |
| BitLocker Status Check (Windows only) | Show BitLocker status and available recovery key information using the native `manage-bde` utility | N/A (system utility)                        |

## ⚠️ Important Notes

* Several features require **Administrator** privileges on Windows (e.g., BitLocker checks and full-system scans). The script attempts to self-elevate on launch when appropriate.
* RAR cracking requires the system `unrar` (or compatible) utility to be installed and available in the system `PATH` because the `rarfile` Python package depends on it.
* This tool is intended for **authorized use only** — only test systems and files for which you have explicit permission.

## ⚙️ Dependencies & Installation

Install required Python packages (recommended to use a virtual environment):

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate     # Windows (PowerShell/CMD)

pip install --upgrade pip
pip install pyzipper pikepdf rarfile msoffcrypto python-docx python-pptx PyPDF2 openpyxl pypiwin32
```

Additional system dependency for RAR support:

* **unrar** (install via your system package manager or official binary and ensure it is on `PATH`)

## 🚀 Usage

Save the script as `encrypt_breaker.py` and run it from your shell.

```bash
python encrypt_breaker.py
```

The script will present an interactive menu. Enter the number for the task you want to run and follow prompts (file paths, wordlist location, hash value, etc.).

Example: cracking a single hash using a wordlist

1. Start the script.
2. Choose `2. Hash to Plain Text` (or similar menu option).
3. Enter the hash value, for example:

```
5d41402abc4b2a76b9719d911017c592
```

4. Enter the path to your wordlist:

```
/path/to/wordlist.txt
```

The script will run a dictionary attack and display progress (custom progress bar) and results.

## 💻 Code Structure Highlights

* `custom_progress_bar` — generator to provide animated progress feedback in the console
* `crack_hash` / `crack_hashes_in_file` — core dictionary attack functions for supported hash types
* `decrypt_file` — handles ZIP / RAR / PDF / Office file decryption attempts with robust exception handling
* `is_admin` — uses `ctypes` to detect and request Administrator elevation on Windows
* `get_bitlocker_status` / `get_recovery_key` — use Windows `manage-bde` via `subprocess` to retrieve BitLocker info

## 🧩 Example Menu (conceptual)

```
1) Generate Hash
2) Hash -> Plain Text (single)
3) Hash -> Plain Text (file)
4) Decrypt File (ZIP/RAR/PDF/Office)
5) Scan Folder for Protected Files
6) BitLocker Status (Windows only)
7) Exit
```

## 🧰 Troubleshooting

* If RAR decryption fails with a `rarfile` error, confirm `unrar` is installed and accessible in your `PATH`.
* If BitLocker functions are not available, ensure you're running the script as Administrator on Windows and that `manage-bde` is present (Windows 8 / Server 2012 and later normally include it).
* For Office file formats, make sure the document is actually password-protected and not just read-only or corrupt.

## 📝 Example `requirements.txt`

```
pyzipper
pikepdf
rarfile
msoffcrypto
python-docx
python-pptx
PyPDF2
openpyxl
pypiwin32
```

