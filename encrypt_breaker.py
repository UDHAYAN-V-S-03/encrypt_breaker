import hashlib
import os
import sys
import time
import io
import string
import ctypes
import subprocess
import wmi
import re
import pyzipper
import pikepdf
import rarfile
from zipfile import ZipFile, BadZipFile
import msoffcrypto
from docx import Document
from pptx import Presentation
from PyPDF2 import PdfReader
import xml.etree.ElementTree as ET
import openpyxl


def hash_text(plain_text, algorithm='md5'):
    """Convert plain text to hash using the specified hashing algorithm."""
    hash_func = hashlib.new(algorithm)
    hash_func.update(plain_text.encode('utf-8'))
    return hash_func.hexdigest()

def custom_progress_bar(iterable, desc='', total=None, show_count=True):
    """Custom animated progress bar for better visual feedback."""
    if total is None:
        total = len(iterable)
    
    bar_length = 40  # Length of the progress bar
    completed_symbol = '█'  # Symbol for completed part of the bar
    pending_symbol = '░'    # Symbol for pending part of the bar
    
    # Initialize the progress bar
    sys.stdout.write(f'\r{desc}: |{"░" * bar_length}| 0/{total} (0%) Complete')
    sys.stdout.flush()
    
    for i, item in enumerate(iterable):
        percent = (i + 1) / total
        filled_length = int(bar_length * percent)
        bar = completed_symbol * filled_length + pending_symbol * (bar_length - filled_length)
        
        # Adjust the progress message based on completion
        if show_count:
            message = f'\r{desc}: |{bar}| {i + 1}/{total} ({int(percent * 100)}%) Completed'
        else:
            message = f'\r{desc}: |{bar}| {int(percent * 100)}% Completed'
        
        # Output the progress bar
        sys.stdout.write(message)
        sys.stdout.flush()
        
        yield item
        time.sleep(0.05)  # Simulate work
    
    # Finalize the progress bar
    sys.stdout.write(f'\r{desc}: |{completed_symbol * bar_length}| {total}/{total} (100%) Completed\n')
    sys.stdout.flush()

def crack_hash(hash_value, wordlist_path):
    """Crack the hash value using a dictionary attack with all available algorithms."""
    algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    
    try:
        with open(wordlist_path, 'r') as wordlist:
            candidates = [line.strip() for line in wordlist]
        
        for candidate in custom_progress_bar(candidates, desc="Cracking hash", show_count=True):
            for algorithm in algorithms:
                if hash_text(candidate, algorithm) == hash_value:
                    return candidate, algorithm, None
    except Exception as e:
        return None, None, f"Error reading wordlist: {e}"
    
    return None, None, None

def crack_hashes_in_file(file_path, wordlist_path):
    """Crack hash values in a file using a dictionary attack with all available algorithms."""
    if not os.path.isfile(file_path):
        return "Check the path or file name of the file containing hashes."
    
    try:
        with open(file_path, 'r') as hash_file:
            hashes = hash_file.read().splitlines()

        results = []
        for hash_value in custom_progress_bar(hashes, desc="Cracking hashes in file", show_count=True):
            cracked_password, algorithm, error = crack_hash(hash_value, wordlist_path)
            if error:
                return error
            if cracked_password:
                results.append(f"Hash Value: {hash_value}\nCracked Password: {cracked_password}\nAlgorithm: {algorithm}\n")
        
        if not results:
            results.append("No valid password found for any hash value.")
        
        return "".join(results)
    
    except Exception as e:
        return f"Error reading hash file: {e}"

def decrypt_file(file_path, password_list, file_type):
    """Attempt to decrypt a file using passwords from the provided list."""
    results = ""
    
    if file_type == 'zip':
        try:
            with pyzipper.AESZipFile(file_path, 'r', compression=pyzipper.ZIP_LZMA) as zf:
                for password in custom_progress_bar(password_list, desc="Cracking ZIP file", show_count=True):
                    zf.pwd = password.encode('utf-8')
                    try:
                        zf.extractall()  # Try extracting with the current password
                        results += f"Success: Password found - {password}\n"
                        return results
                    except (RuntimeError, pyzipper.BadZipFile):
                        continue
        except (RuntimeError, pyzipper.BadZipFile):
            pass
    
    elif file_type == 'rar':
        try:
            with rarfile.RarFile(file_path) as rf:
                for password in custom_progress_bar(password_list, desc="Cracking RAR file", show_count=True):
                    try:
                        rf.extractall(pwd=password)
                        results += f"Success: Password found - {password}\n"
                        return results
                    except (rarfile.BadRarFile, rarfile.RarWrongPassword):
                        continue
        except rarfile.BadRarFile:
            pass
    
    elif file_type == 'pdf':
        try:
            for password in custom_progress_bar(password_list, desc="Cracking PDF file", show_count=True):
                try:
                    pdf = pikepdf.open(file_path, password=password)
                    results += f"Success: Password found - {password}\n"
                    return results
                except pikepdf.PasswordError:
                    continue
        except Exception as e:
            results += f"Unexpected error: {e}\n"
    
    elif file_type in ['docx', 'pptx', 'xlsx']:
        try:
            for password in custom_progress_bar(password_list, desc=f"Cracking {file_type.upper()} file", show_count=True):
                try:
                    with open(file_path, 'rb') as f:
                        office_file = msoffcrypto.OfficeFile(f)
                        office_file.load_key(password=password)
                        decrypted_io = io.BytesIO()
                        office_file.decrypt(decrypted_io)
                        
                        # Test opening decrypted content
                        if file_type == 'docx':
                            Document(decrypted_io)
                        elif file_type == 'pptx':
                            Presentation(decrypted_io)
                        elif file_type == 'xlsx':
                            openpyxl.load_workbook(decrypted_io)
                        
                        results += f"Success: Password found - {password}\n"
                        return results
                except (msoffcrypto.exceptions.InvalidKeyError, msoffcrypto.exceptions.DecryptionError):
                    continue
        except Exception as e:
            results += f"Unexpected error: {e}\n"
    
    results += "The file is not protected or failed to crack.\n"
    return results

def process_file_decryption(file_path, password_list):
    """Handle file decryption based on file type."""
    file_type = os.path.splitext(file_path)[1].lower()
    results = ""
    
    if file_type == '.zip':
        if not is_zip_protected(file_path):
            results += "The ZIP file is not protected."
        else:
            results += decrypt_file(file_path, password_list, 'zip')
    
    elif file_type == '.rar':
        if not is_rar_protected(file_path):
            results += "The RAR file is not protected."
        else:
            results += decrypt_file(file_path, password_list, 'rar')
    
    elif file_type == '.pdf':
        if not is_pdf_protected(file_path):
            results += "The PDF file is not protected."
        else:
            results += decrypt_file(file_path, password_list, 'pdf')
    
    elif file_type in ['.docx', '.pptx', '.xlsx']:
        if not is_office_protected(file_path):
            results += f"The {file_type.upper()} file is not protected."
        else:
            results += decrypt_file(file_path, password_list, file_type[1:])
    
    else:
        results += "Unsupported file type. Only ZIP, RAR, PDF, DOCX, PPTX, XLSX files are supported.\n"
    
    return results

def get_valid_file_path(prompt_message):
    """Prompt the user for a file path and validate its existence."""
    file_path = input(prompt_message)
    while not os.path.isfile(file_path):
        print("Error: File does not exist. Please check the path and try again.")
        file_path = input(prompt_message)
    return file_path

def get_valid_wordlist_path():
    """Prompt the user for the wordlist path and validate the file extension."""
    wordlist_path = input("Enter the path to the password wordlist file (.txt): ")
    while not (os.path.isfile(wordlist_path) and wordlist_path.endswith('.txt')):
        print("Error: Invalid file path or incorrect file format. Only .txt files are supported.")
        wordlist_path = input("Enter the path to the password wordlist file (.txt): ")
    return wordlist_path

def display_results(results):
    """Display results in the terminal."""
    print("\n--- Results ---")
    print(results)

def load_wordlist():
    """Load and validate the wordlist path."""
    wordlist_path = get_valid_wordlist_path()
    try:
        with open(wordlist_path, 'r') as file:
            return [line.strip() for line in file]
    except Exception as e:
        print(f"Error reading wordlist: {e}")
        return []

def is_zip_protected(file_path):
    """Check if a ZIP file is password protected."""
    try:
        with pyzipper.AESZipFile(file_path, 'r', compression=pyzipper.ZIP_LZMA) as zf:
            zf.testzip()  # Check if we can read the file without a password
            return False
    except (RuntimeError, pyzipper.BadZipFile):
        return True

def is_rar_protected(file_path):
    """Check if a RAR file is password protected."""
    try:
        with rarfile.RarFile(file_path) as rf:
            # Attempt to read a single file from the archive to see if it's protected
            rf.read(rf.namelist()[0])  # Try to read the first file in the RAR archive
            return False
    except rarfile.BadRarFile:
        # The file is not a valid RAR file
        return False
    except rarfile.RarWrongPassword:
        # The RAR file is password protected
        return True
    except rarfile.PasswordRequired:
        # The RAR file is password protected
        return True
    except Exception as e:
        print(f"Error checking RAR file {file_path}: {e}")
        return False

def is_pdf_protected(file_path):
    """Check if a PDF file is password protected."""
    try:
        pikepdf.open(file_path)  # Attempt to open the file without a password
        return False
    except pikepdf.PasswordError:
        return True
    except Exception:
        return False

def is_office_protected(file_path):
    """Check if an Office file is password protected."""
    file_type = os.path.splitext(file_path)[1].lower()
    try:
        with open(file_path, 'rb') as f:
            office_file = msoffcrypto.OfficeFile(f)
            office_file.load_key(password='')  # Attempt to open without a password
            office_file.decrypt(io.BytesIO())  # Try to decrypt without password
            return False  # File is not protected
    except (msoffcrypto.exceptions.InvalidKeyError, msoffcrypto.exceptions.DecryptionError):
        return True  # File is protected
    except Exception as e:
        return f"Error occurred: {e}"  # Handle unexpected errors gracefully

def scan_protected_files(folder_path):
    """Scan a folder for protected files and list them."""
    protected_files = []
    total_files = 0
    total_protected = 0

    # Collect all files in the directory first
    all_files = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    
    total_files = len(all_files)  # Total number of files to scan

    # Filter and check for protected files
    for file_path in custom_progress_bar(all_files, desc="Scanning files", show_count=True):
        file_extension = os.path.splitext(file_path)[1].lower()
        is_protected = False

        if file_extension == '.zip':
            is_protected = is_zip_protected(file_path)
        elif file_extension == '.rar':
            is_protected = is_rar_protected(file_path)
        elif file_extension == '.pdf':
            is_protected = is_pdf_protected(file_path)
        elif file_extension in ['.docx', '.pptx', '.xlsx']:
            is_protected = is_office_protected(file_path)

        if is_protected:
            protected_files.append(file_path)
            total_protected += 1
    
    return total_files, total_protected, protected_files


def full_scan_windows():
    """Perform a full system scan on Windows by iterating over all drives."""
    drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]

    all_files = []
    protected_files = []
    
    for drive in drives:
        print(f"\nScanning drive {drive}")
        drive_files, drive_protected, drive_protected_files = scan_protected_files(drive)
        all_files.extend(drive_files)
        protected_files.extend(drive_protected_files)

        print(f"\nTotal files scanned on {drive}: {drive_files}")
        print(f"Total protected files on {drive}: {drive_protected}")
        if drive_protected > 0:
            print("Protected files list:")
            for pf in drive_protected_files:
                print(pf)
        else:
            print("No files are protected on this drive.")

    # If there are files to scan, use progress bar
    if all_files:
        total_files = len(all_files)
        total_protected = len(protected_files)
        
        print("\nScanning system files...")
        for file_path in custom_progress_bar(all_files, desc="Scanning system files", show_count=True):
            
            pass

        if total_protected == 0:
            print("No files are protected.")
        else:
            print(f"\nTotal files scanned: {total_files}")
            print(f"Total protected files: {total_protected}")
            print("Protected files list:")
            for pf in protected_files:
                print(pf)

        # Check if the file is protected
        if is_zip_protected(file_path) or is_rar_protected(file_path) or is_pdf_protected(file_path) or is_office_protected(file_path):
            protected_files.append(file_path)
            total_protected += 1
            results += f"Protected file: {file_path}\n"
        else:
            results += f"Not protected: {file_path}\n"
                
            display_results(results)
    
    if total_protected == 0:
        print("No files are protected.")
    else:
        print(f"\nTotal files scanned: {total_files}")
        print(f"Total protected files: {total_protected}")
        print("Protected files list:")
        for pf in protected_files:
            print(pf)

# Function to check if the script is run as administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("This script requires administrator privileges. Restarting with elevated privileges...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

# Initialize WMI client for BitLocker and Drive Query
c = wmi.WMI(namespace='root\\CIMv2\\Security\\MicrosoftVolumeEncryption')
wmi_drive = wmi.WMI()

# Function to list all available disk drives including external drives
def get_available_drives():
    drives = []
    for disk in wmi_drive.Win32_LogicalDisk(DriveType=3):  # DriveType=3 for local disks
        drives.append(disk.DeviceID)
    for disk in wmi_drive.Win32_LogicalDisk(DriveType=2):  # DriveType=2 for removable disks
        drives.append(disk.DeviceID)
    return drives

# Function to get BitLocker status and format the output
def format_bitlocker_status(output):
    # Split the output into lines
    lines = output.splitlines()
    formatted_output = []
    
    # Variable to track if any Key Protector details were found
    key_protectors_found = False

    # Process each line to extract and format the necessary information
    for line in lines:
        # Skip unwanted lines
        if "Disk volumes that can be protected with BitLocker Drive Encryption" in line:
            continue
        if "BitLocker Drive Encryption: Configuration Tool" in line or "Copyright" in line:
            continue
        
        if "Volume" in line:
            formatted_output.append(f"{line.strip()}:")
        elif "Size" in line or "BitLocker Version" in line or "Conversion Status" in line:
            formatted_output.append(f"    {line.strip()}")
        elif "Percentage Encrypted" in line or "Encryption Method" in line:
            formatted_output.append(f"    {line.strip()}")
        elif "Protection Status" in line or "Lock Status" in line:
            formatted_output.append(f"    {line.strip()}")
        elif "Identification Field" in line or "Automatic Unlock" in line:
            formatted_output.append(f"    {line.strip()}")
        elif "Key Protectors" in line:
            formatted_output.append(f"    Key Protectors:")
            continue  # To manage indentation for key protectors
        elif line.strip():  # For key protector details
            formatted_output.append(f"        {line.strip()}")
            key_protectors_found = True  # Mark that we found at least one key protector

    # Check if key protectors were found, if not append "None Found"
    if "Key Protectors:" in formatted_output and not key_protectors_found:
        formatted_output.append(f"        None Found")  # Append "None Found"
    
    return "\n".join(formatted_output)

def get_bitlocker_status():
    # Run the manage-bde command and capture the output
    try:
        result = subprocess.run(
            ["manage-bde", "-status"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        return ""
    
    
# Function to get BitLocker recovery key
def get_recovery_key(drive_letter):
    try:
        command = f"manage-bde -protectors -get {drive_letter}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            recovery_info = result.stdout.splitlines()
            is_printing = False

            print(f"\nRecovery Information for {drive_letter}:\n")

            for line in recovery_info:
                if "All Key Protectors" in line:
                    is_printing = True

                if is_printing:
                    if "BitLocker Drive Encryption" in line or "Copyright" in line:
                        continue
                    print(line)

        else:
            print("Failed to retrieve the recovery key. Ensure BitLocker is enabled for this drive.")

    except Exception as e:
        print(f"Error retrieving recovery key: {str(e)}")

def main():
    print("\nEncrypt Breaker - Password Cracking Tool\n")
    while True:
        try:
            print("1. Plain Text to Hash")
            print("2. Hash to Plain Text")
            print("3. Hashed File to Plain Text")
            print("4. File Decryption (ZIP, RAR, PDF, Office Files)")
            print("5. Scan for Protected Files")
            print("6. Full Scan")
            print("7. Check BitLocker Status")
            print("8. Exit")
            choice = input("Select an option: ")
            
            if choice not in {'1', '2', '3', '4', '5', '6', '7', '8'}:
                print("Select a valid option.")
                continue            

            if choice == '9':
                print("\nGoodbye!\n")
                break
            
            results = ""

            if choice == '1':
                plain_text = input("Enter the plain text: ")
                algorithms = ['md5', 'sha1', 'sha256', 'sha512']
                for algo in algorithms:
                    hash_value = hash_text(plain_text, algo)
                    results += f"{algo.upper()}: {hash_value}\n"

            elif choice == '2':
                hash_value = input("Enter the hash value: ")
                wordlist_path = input("Enter the path to the wordlist: ")
                cracked_password, algorithm, error = crack_hash(hash_value, wordlist_path)
    
                if error:
                    results = f"Error: {error}\n"
                elif algorithm:
                    results = f"Hash Value: {hash_value}\nAlgorithm: {algorithm}\nPlain Text: {cracked_password}\n"
                else:
                    results = f"Hash Value: {hash_value}\nPlain Text: No valid password found.\n"
                    
            elif choice == '3':
                hashed_file_path = input("Enter the path to the file containing hash values: ")
                wordlist_path = input("Enter the path to the wordlist: ")
                results = crack_hashes_in_file(hashed_file_path, wordlist_path)

            elif choice == '4':
                print("Only supports for .docx, .pptx,.xlsx format files only.")
                file_path = get_valid_file_path("Enter the path of the file to decrypt: ")
                file_type = os.path.splitext(file_path)[1].lower()

                password_list = load_wordlist()
                if not password_list:
                    results += "Failed to load wordlist. Please check the file and try again.\n"
                else:
                    results += process_file_decryption(file_path, password_list)

            elif choice == '5':
                folder_path = input("Enter the folder path to scan for protected files: ")
                if not os.path.isdir(folder_path):
                    print("Invalid path. Please try again.")
                    continue
                total_files, total_protected, protected_files = scan_protected_files(folder_path)
        
                if total_protected == 0:
                    results = (f"Path Scanned: {folder_path}\n"
                        f"Total Files: {total_files}\n"
                        f"No protected files found.")
                else:
                    results = (f"Path Scanned: {folder_path}\n"
                    f"Total Files: {total_files}\n"
                    f"Total Protected Files: {total_protected}\n"
                    f"Protected Files List:\n" + "\n".join(protected_files))
                    
            elif choice == '6':
                confirm = input("This will scan the entire system. Are you sure? (y/n): ")
                if confirm.lower() == 'y':
                    full_scan_windows()
            
            elif choice == '7':
                # Check BitLocker status
                print("Checking BitLocker Status...")
                formatted_status = get_bitlocker_status()
                if formatted_status:
                    print(formatted_status)

                # List available drives
                available_drives = get_available_drives()
                print("\nAvailable Drives:", ", ".join(available_drives))

                # Prompt for drive letter to retrieve BitLocker recovery key
                drive_letter = ""
                while True:
                    drive_letter = input("Enter the drive letter to retrieve the BitLocker recovery key (e.g., C:): ").strip()
                    if drive_letter in available_drives:
                        break
                    else:
                        print("Invalid drive letter. Please select from available drives.")

                get_recovery_key(drive_letter)
                             
            display_results(results)
                    
        except KeyboardInterrupt:
            print("\nProcess interrupted. Returning to the main menu...")
            # Ensure the main menu is displayed again after interruption
            continue
          
if __name__ == "__main__":
    main()