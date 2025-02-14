#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import shlex
import threading
import re
from concurrent.futures import ThreadPoolExecutor
import pytz
from datetime import datetime
import hashlib
import base64

# ======================================================================================
# GLOBAL DEFINITIONS
# ======================================================================================

# The user's desktop path, used as a reference for storing a log file.
desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")

# The path for the log file stored on the desktop.
log_file = os.path.join(desktop_path, "dump_analysis_log.txt")

# A lock object for controlling write access to the log file from multiple threads.
log_lock = threading.Lock()

# ======================================================================================
# TIME AND LOGGING UTILITIES
# ======================================================================================

def get_german_time() -> str:
    """
    Returns a string representing the current time in Germany (Europe/Berlin) in the format YYYY-MM-DD HH:MM:SS.
    This is used for consistent timestamping in logs.
    """
    tz = pytz.timezone("Europe/Berlin")
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")


def setup_log_file() -> None:
    """
    Ensures that the desktop directory exists and then appends a separation line
    and a "Log Start" line with the current German timestamp to the log file.
    This is typically called once at the beginning of the main program to start logging.
    """
    os.makedirs(desktop_path, exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as log:
        log.write("\n=========\n")
        log.write(f"Log Start: {get_german_time()}\n")


def log_message(message: str, level: str = "INFO") -> None:
    """
    Appends a log message to the global log file in a thread-safe manner.

    Args:
        message (str): The content of the message to be logged.
        level (str): The log level (e.g., INFO, WARNING, ERROR).
    """
    with log_lock:
        with open(log_file, "a", encoding="utf-8") as log:
            timestamp = get_german_time()
            log.write(f"[{timestamp} - {level}] {message}\n")

# ======================================================================================
# DIRECTORY AND FILE UTILITIES
# ======================================================================================

def get_valid_directory(prompt: str) -> str:
    """
    Continuously prompts the user for a directory path until a valid directory is provided
    or 'exit' is entered. If 'exit' is entered, returns None.

    Args:
        prompt (str): The prompt message shown to the user.

    Returns:
        str: A valid directory path or None if the user types 'exit'.
    """
    while True:
        path = input(prompt).strip()
        if path.lower() == "exit":
            return None
        if os.path.isdir(path):
            return path
        print(f"Error: The path '{path}' does not exist or is not a directory!")
        log_message(f"Invalid directory input: {path}", "WARNING")


def list_files_in_directory(directory: str) -> list:
    """
    Attempts to list all files in a given directory. Handles permission errors,
    file not found errors, or unknown exceptions. Logs appropriate messages and returns
    an empty list if an error occurs or if no files exist in the directory.

    Args:
        directory (str): The directory path to list files from.

    Returns:
        list: A list of absolute file paths. May be empty if no files are found or upon error.
    """
    try:
        files = [
            os.path.join(directory, f)
            for f in os.listdir(directory)
            if os.path.isfile(os.path.join(directory, f))
        ]
        if not files:
            log_message(f"No files found in directory {directory}.", "WARNING")
        else:
            print("\nFound the following files:")
            for file in files:
                print(f"- {file}")
            log_message(f"Files in directory {directory}: {files}", "INFO")
        return files
    except PermissionError:
        log_message(f"Permission denied: Cannot access directory {directory}", "ERROR")
        print(f"Error: Permission denied for directory {directory}!")
        return []
    except FileNotFoundError:
        log_message(f"Directory {directory} does not exist.", "ERROR")
        print(f"Error: Directory {directory} does not exist!")
        return []
    except Exception as e:
        log_message(f"Unknown error: {str(e)}", "ERROR")
        print(f"An unknown error occurred: {str(e)}")
        return []

# ======================================================================================
# DEPENDENCY CHECK
# ======================================================================================

def check_dump_dependencies() -> None:
    """
    Verifies if the system contains two essential external commands for this script:
    'strings' and 'grep'. If any of these commands are missing, the script will exit
    with an error message.
    """
    required_commands = ['strings', 'grep']
    missing = [cmd for cmd in required_commands if not shutil.which(cmd)]
    if missing:
        print(
            f"Error: The following required commands are missing: {', '.join(missing)}. "
            "Please install them and try again."
        )
        sys.exit(1)

# ======================================================================================
# DUMP CONVERSION TO TEXT
# ======================================================================================

def convert_dump_to_txt(dump_file: str) -> str:
    """
    Uses the 'strings' command to convert a dump file (binary or otherwise) into a text file.
    Stores the resulting text file in the same directory as the original dump file,
    named <dump_file>.txt.

    Args:
        dump_file (str): The absolute path of the dump file.

    Returns:
        str: The path to the newly created text file, or an empty string if conversion fails.
    """
    txt_filename = os.path.basename(dump_file) + ".txt"
    txt_filepath = os.path.join(os.path.dirname(dump_file), txt_filename)
    try:
        result = subprocess.run(
            ["strings", dump_file],
            capture_output=True,
            text=True,
            check=True
        )
        with open(txt_filepath, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        print(f"Conversion successful: {dump_file} -> {txt_filepath}")
        log_message(f"Converted {dump_file} to {txt_filepath}", "INFO")
        return txt_filepath
    except subprocess.CalledProcessError as e:
        error_message = f"Conversion failed for {dump_file}: {e.stderr if e.stderr else str(e)}"
        print(error_message)
        log_message(error_message, "ERROR")
        return ""


def convert_files(dump_files: list) -> list:
    """
    Given a list of dump file paths, converts each one using 'convert_dump_to_txt' and logs the results.

    Args:
        dump_files (list): A list of file paths to be converted from dump format to .txt

    Returns:
        list: A list of resulting .txt file paths. Some may be missing if conversion failed.
    """
    converted = []
    for df in dump_files:
        print(f"Converting file {df} ...")
        log_message(f"Converting file {df} ...", "INFO")
        txt = convert_dump_to_txt(df)
        if txt:
            print(f"File {df} conversion successful.")
            log_message(f"File {df} conversion successful.", "INFO")
            converted.append(txt)
        else:
            print(f"File {df} conversion failed.")
            log_message(f"File {df} conversion failed.", "ERROR")
    return converted

# ======================================================================================
# GREP-BASED SEARCH UTILS
# ======================================================================================

def search_string_or_regex(file_path: str, pattern: str, is_regex: bool = False) -> None:
    """
    Uses the grep command to search for a given pattern in a text file. Depending on 'is_regex',
    it either interprets the pattern as a literal string or as an extended regex pattern.

    Args:
        file_path (str): The path to the text file to search in.
        pattern (str): The literal string or regex pattern to find.
        is_regex (bool): If True, uses 'grep -Eio'. If False, uses 'grep -Fi'.
    """
    try:
        print(f"Searching file {file_path} for pattern '{pattern}' ...")
        log_message(f"Searching {file_path} for pattern '{pattern}'", "INFO")
        safe_file = shlex.quote(file_path)
        safe_pattern = shlex.quote(pattern)
        if is_regex:
            cmd = f"grep -Eio {safe_pattern} {safe_file}"
        else:
            cmd = f"grep -Fi {safe_pattern} {safe_file}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            output = result.stdout.strip()
            if output:
                print(f"\nMatches found in file {file_path}:")
                print("\n\n".join(" " + line for line in output.splitlines()))
                log_message(f"Matches in {file_path}:\n{output}", "INFO")
            else:
                print(f"No matches found in file {file_path}.")
                log_message(f"No matches in {file_path}.", "INFO")
        elif result.returncode == 1:
            # 1 means no matches found
            print(f"No matches found in file {file_path}.")
            log_message(f"No matches in {file_path}.", "INFO")
        else:
            # Any other return code indicates an error or unusual grep exit status
            error_msg = f"Command failed: {cmd}\nError: {result.stderr.strip()}"
            print(f"Error in file {file_path}. See log for details.")
            log_message(error_msg, "ERROR")
    except Exception as e:
        error_msg = f"Unknown error in file {file_path}: {str(e)}"
        print(error_msg)
        log_message(error_msg, "ERROR")


def search_files(files: list, pattern: str, is_regex: bool = False) -> None:
    """
    Searches for a pattern in multiple text files concurrently using ThreadPoolExecutor.
    Each file is processed by 'search_string_or_regex'.

    Args:
        files (list): A list of text file paths.
        pattern (str): The pattern to look for (literal or regex).
        is_regex (bool): If True, treat pattern as extended regex; otherwise as a literal string.
    """
    if not files:
        print("Error: No files to process!")
        return
    print(f"\nSearching {len(files)} files...")
    log_message(f"Starting search for pattern ({'regex' if is_regex else 'string'}): '{pattern}'", "INFO")

    max_workers = min(4, os.cpu_count() or 2)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(lambda f: search_string_or_regex(f, pattern, is_regex), files))

# ======================================================================================
# VIEW LOG
# ======================================================================================

def view_log_file() -> None:
    """
    Prints the path of the log file and displays its entire contents, if it exists.
    """
    try:
        print(f"\nLog file path: {log_file}\n")
        print("Log file contents:\n")
        with open(log_file, "r", encoding="utf-8") as log:
            print(log.read())
    except FileNotFoundError:
        print(f"Log file {log_file} not found. Please ensure the log has been generated.")

# ======================================================================================
# PASSWORD FILE SEARCH
# ======================================================================================

def validate_password_file(path: str) -> bool:
    """
    Checks whether the given password manager file (path) exists and is non-empty.

    Args:
        path (str): The path to the password manager file.

    Returns:
        bool: True if file exists and is not empty; otherwise False.
    """
    if not os.path.isfile(path):
        print(f"Error: File {path} does not exist!")
        log_message(f"Invalid password file: {path}", "ERROR")
        return False
    if os.path.getsize(path) == 0:
        print("Error: Password file is empty!")
        log_message(f"Empty password file: {path}", "ERROR")
        return False
    return True


def search_from_password_manager_file(files: list, password_file: str) -> None:
    """
    Reads patterns from the given password manager file, each line being either:
      - "STRING:<some text>"
      - "REGEX:<some pattern>"
      - Or commented out with '#' (those lines are displayed as commentary).
    The extracted patterns are then passed to 'search_files' to search across the given text files.

    Args:
        files (list): A list of text files to be searched.
        password_file (str): The path to the password manager file containing search rules.
    """
    if not validate_password_file(password_file):
        return
    try:
        with open(password_file, "r", encoding="utf-8") as f:
            lines = [line.rstrip() for line in f]
        print(f"\nLoaded {len(lines)} lines from the password file.")
        log_message(f"Loaded password file: {password_file} ({len(lines)} lines)", "INFO")

        for idx, line in enumerate(lines, 1):
            # If the line starts with '#', treat it as a comment
            if line.lstrip().startswith("#"):
                sep = "=" * 40
                print(f"\n{sep}\n{line}\n{sep}\n")
                log_message(f"Comment on line {idx}: {line}", "INFO")
                continue

            # If it starts with STRING:
            if line.startswith("STRING:"):
                pattern = line[7:].strip()
                if not pattern:
                    log_message(f"Line {idx}: Empty string rule, skipping", "WARNING")
                    continue
                search_files(files, pattern, False)

            # If it starts with REGEX:
            elif line.startswith("REGEX:"):
                pattern = line[6:].strip()
                if not pattern:
                    log_message(f"Line {idx}: Empty regex rule, skipping", "WARNING")
                    continue
                try:
                    re.compile(pattern)  # Test if it's a valid regex
                    search_files(files, pattern, True)
                except re.error as e:
                    log_message(f"Line {idx}: Invalid regex '{pattern}': {str(e)}", "ERROR")
                    print(f"Warning: Skipping invalid regex on line {idx}")

            # If it's an empty line, ignore
            elif line.strip() == "":
                continue

            # Otherwise, unknown format
            else:
                log_message(f"Line {idx}: Unknown rule format '{line}', skipping", "WARNING")
                print(f"Warning: Unknown rule format on line {idx}, skipping")

    except Exception as e:
        error_msg = f"Error processing password file: {str(e)}"
        print(error_msg)
        log_message(error_msg, "ERROR")

# ======================================================================================
# PM ANALYSIS: MULTI-FILE SALT/KEY SEARCH
# ======================================================================================

def pm_analysis(txt_files: list) -> None:
    """
    PM Analysis Function (using grep instead of Python's re.findall).
    This function takes a list of text files (txt_files) and a chosen directory to save results.
    It searches for various salt/key patterns (both hex and base64 variants) across all provided files.

    1) Prompts the user for a directory in which to store analysis results.
    2) Uses grep to match each pattern in each provided text file.
    3) Collects unique matches in memory.
    4) Writes a summary of all found matches to 'pm_analysis_results.txt' and also writes
       each pattern's matches in separate files under the 'pm_analysis' subdirectory.

    Args:
        txt_files (list): A list of .txt file paths to analyze for potential salt/key data.
    """

    if not txt_files:
        print("No txt files provided for PM Analysis.")
        return

    print("\n--- User login credentials Analysis ---")
    print("This function will search for potential salt and key patterns in the provided txt files.")
    print("All findings will be stored in separate .txt files, grouped by pattern type, inside a 'pm_analysis' subfolder.")
    print("A summary file named 'pm_analysis_results.txt' will also be generated in the same folder.\n")

    # Prompt user for the directory where results should be stored
    result_dir = get_valid_directory("Enter the directory where PM Analysis results should be saved: ")
    if not result_dir:
        print("Returning to main menu.")
        return

    pm_result_dir = os.path.join(result_dir, "pm_analysis")
    os.makedirs(pm_result_dir, exist_ok=True)

    # Patterns that match various hex or base64 lengths:
    patterns = {
        "hex_salt_32": r"\b[a-fA-F0-9]{32}\b",
        "hex_salt_64": r"\b[a-fA-F0-9]{64}\b",
        "b64_salt_24": r"\b[A-Za-z0-9+/]{22}={0,2}\b",
        "b64_salt_44": r"\b[A-Za-z0-9+/]{44}={0,2}\b",
        "hex_key_64":  r"\b[a-fA-F0-9]{64}\b",
        "hex_key_128": r"\b[a-fA-F0-9]{128}\b",
        "b64_key_44":  r"\b[A-Za-z0-9+/]{44}={0,2}\b",
        "b64_key_88":  r"\b[A-Za-z0-9+/]{88}={0,2}\b"
    }

    # A dictionary to hold sets of matches for each pattern
    results = {key: set() for key in patterns}

    # For each text file, run grep on each pattern
    for txt_file in txt_files:
        print(f"\nAnalyzing file: {txt_file}")
        if not os.path.isfile(txt_file):
            print(f"  - Skipped: {txt_file} is not a valid file.")
            continue

        for key, pattern in patterns.items():
            cmd = ["grep", "-Eo", pattern, txt_file]
            try:
                process = subprocess.run(cmd, capture_output=True, text=True)
                if process.returncode == 0:
                    found_lines = process.stdout.strip().split("\n")
                    for m in found_lines:
                        if m.strip():
                            # Add each match to a set to avoid duplicates across multiple files
                            results[key].add(m.strip())
                elif process.returncode == 1:
                    # 1 means no matches found in this file, do nothing
                    pass
                else:
                    # If grep returns something other than 0 or 1, it's an error
                    log_message(
                        f"grep error for pattern '{key}' on file '{txt_file}': {process.stderr.strip()}",
                        "ERROR"
                    )
            except Exception as ex:
                log_message(
                    f"Error running grep for pattern '{key}' on file '{txt_file}': {str(ex)}",
                    "ERROR"
                )

    # Write all results into a summary file
    summary_file = os.path.join(pm_result_dir, "pm_analysis_results.txt")
    try:
        with open(summary_file, "w", encoding="utf-8") as sf:
            for key in patterns:
                sf.write(f"=== {key} ===\n")
                if results[key]:
                    for match in sorted(results[key]):
                        sf.write(match + "\n")
                else:
                    sf.write("No matches found.\n")
                sf.write("\n")
        print(f"\nSummary of User login credentials Analysis results saved in {summary_file}")
        log_message(f"User login credentials Analysis summary saved in {summary_file}", "INFO")
    except Exception as e:
        print(f"Error writing summary results: {e}")
        log_message(f"Error writing summary results: {e}", "ERROR")

    # Write each pattern's results into a separate file
    for key in patterns:
        output_file = os.path.join(pm_result_dir, f"pm_analysis_{key}.txt")
        try:
            with open(output_file, "w", encoding="utf-8") as outf:
                if results[key]:
                    for match in sorted(results[key]):
                        outf.write(match + "\n")
                else:
                    outf.write("No matches found.\n")
            print(f"Results for {key} saved in {output_file}")
            log_message(f"User login credentials Analysis results for {key} saved in {output_file}", "INFO")
        except Exception as e:
            print(f"Error writing results to {output_file}: {e}")
            log_message(f"Error writing results to {output_file}: {e}", "ERROR")

    print("\nUser login credentials Analysis completed.")

# ======================================================================================
# PM BRUTEFORCE: TRY SALT/KEY COMBINATIONS
# ======================================================================================

def pm_bruteforce() -> None:
    """
    PM Brute Force Function with Algorithm Selection.

    This function allows the user to choose between two brute force algorithms:
      1. PBKDF2-HMAC-SHA256
      2. Argon2

    For PBKDF2-HMAC-SHA256:
      - The user provides the master password and the iteration count.
      - The derived key is computed using PBKDF2-HMAC-SHA256 and compared with candidate keys.

    For Argon2:
      - The user provides the master password, time cost (iterations), memory cost (in MB), and parallelism.
      - The derived key is computed using Argon2 (Argon2id variant) and compared with candidate keys.

    The function loads candidate salts and keys from files generated by the PM Analysis step.
    For each candidate combination, it computes the derived key and compares it to the candidate key.
    If a match is found, the matching salt and derived key are printed.
    """
    # Import argon2.low_level for Argon2 functionality
    try:
        from argon2 import low_level
    except ImportError:
        print("Error: argon2-cffi module is not installed. Please install it to use Argon2 functionality.")
        return

    print("\n--- PM Brute Force Extended ---")
    print("Select brute force algorithm:")
    print("1. PBKDF2-HMAC-SHA256")
    print("2. Argon2d")
    algo_choice = input("Enter your choice (1 or 2): ").strip()

    # Branch based on the algorithm selected by the user
    if algo_choice == "1":
        # --- PBKDF2-HMAC-SHA256 Branch ---
        master_password = input("Enter the known master password: ").strip()
        if not master_password:
            print("Master password cannot be empty. Returning to main menu.")
            return
        try:
            iteration_count = int(input("Enter the iteration count (e.g., 10000): ").strip())
        except ValueError:
            print("Invalid iteration count. Returning to main menu.")
            return

        def derive_key(salt_bytes: bytes, dklen: int) -> bytes:
            """
            Derives a key using PBKDF2-HMAC-SHA256.
            Args:
                salt_bytes (bytes): The salt as a byte sequence.
                dklen (int): The desired length of the derived key.
            Returns:
                bytes: The derived key.
            """
            return hashlib.pbkdf2_hmac(
                "sha256",
                master_password.encode("utf-8"),
                salt_bytes,
                iteration_count,
                dklen=dklen
            )

        algorithm_used = "PBKDF2-HMAC-SHA256"

    elif algo_choice == "2":
        # --- Argon2 Branch ---
        master_password = input("Enter the known master password: ").strip()
        if not master_password:
            print("Master password cannot be empty. Returning to main menu.")
            return
        try:
            time_cost = int(input("Enter the number of iterations (time cost) for Argon2: ").strip())
        except ValueError:
            print("Invalid time cost value. Returning to main menu.")
            return
        try:
            memory_mb = int(input("Enter the memory cost in MB for Argon2 (e.g., 32 for 32MB): ").strip())
        except ValueError:
            print("Invalid memory cost value. Returning to main menu.")
            return
        # Convert memory from MB to KiB (as required by Argon2)
        memory_cost = memory_mb * 1024
        try:
            parallelism = int(input("Enter the parallelism (number of threads) for Argon2: ").strip())
        except ValueError:
            print("Invalid parallelism value. Returning to main menu.")
            return

        def derive_key(salt_bytes: bytes, dklen: int) -> bytes:
            """
            Derives a key using Argon2 (using the Argon2d variant).
            Args:
                salt_bytes (bytes): The salt as a byte sequence.
                dklen (int): The desired length of the derived key.
            Returns:
                bytes: The derived key.
            """
            return low_level.hash_secret_raw(
                secret=master_password.encode("utf-8"),
                salt=salt_bytes,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=dklen,
                type=low_level.Type.D  # Use Argon2d variant
            )

        algorithm_used = "Argon2d"
    else:
        print("Invalid algorithm selection. Returning to main menu.")
        return

    # Prompt the user for the directory containing PM Analysis results
    pm_result_dir = get_valid_directory("Enter the directory containing the PM Analysis results (should include 'pm_analysis' folder): ")
    if not pm_result_dir:
        print("Returning to main menu.")
        return

    pm_folder = os.path.join(pm_result_dir, "pm_analysis")
    if not os.path.isdir(pm_folder):
        print(f"Error: 'pm_analysis' folder not found in {pm_result_dir}.")
        return

    # Define file paths for candidate salt and key files
    salt_files = {
        "hex_salt_32": os.path.join(pm_folder, "pm_analysis_hex_salt_32.txt"),
        "hex_salt_64": os.path.join(pm_folder, "pm_analysis_hex_salt_64.txt"),
        "b64_salt_24": os.path.join(pm_folder, "pm_analysis_b64_salt_24.txt"),
        "b64_salt_44": os.path.join(pm_folder, "pm_analysis_b64_salt_44.txt")
    }
    key_files = {
        "hex_key_64": os.path.join(pm_folder, "pm_analysis_hex_key_64.txt"),
        "hex_key_128": os.path.join(pm_folder, "pm_analysis_hex_key_128.txt"),
        "b64_key_44": os.path.join(pm_folder, "pm_analysis_b64_key_44.txt"),
        "b64_key_88": os.path.join(pm_folder, "pm_analysis_b64_key_88.txt")
    }

    # Helper function to load candidates from a file, ignoring empty lines
    def load_candidates(file_path: str) -> list:
        if os.path.isfile(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        else:
            return []

    # Helper function to convert a candidate string (salt or key) into bytes based on its encoding
    def candidate_to_bytes(candidate: str, mode: str) -> bytes:
        """
        Converts a candidate string into raw bytes.
        Args:
            candidate (str): The candidate string (salt or key).
            mode (str): "hex" for hexadecimal or "b64" for base64.
        Returns:
            bytes: The corresponding byte sequence.
        """
        if mode == "hex":
            return bytes.fromhex(candidate)
        elif mode == "b64":
            return base64.b64decode(candidate)
        else:
            raise ValueError("Invalid mode for candidate conversion.")

    # Load candidate salts and keys from their respective files
    salt_candidates = []
    for fname in salt_files.values():
        salt_candidates.extend(load_candidates(fname))
    key_candidates = []
    for fname in key_files.values():
        key_candidates.extend(load_candidates(fname))

    if not salt_candidates or not key_candidates:
        print("Insufficient candidate data for brute force. Ensure PM Analysis has generated candidate salt and key files.")
        return

    print(f"Loaded {len(salt_candidates)} salt candidates and {len(key_candidates)} key candidates.")
    log_message(f"PM Brute Force Extended ({algorithm_used}): {len(salt_candidates)} salts, {len(key_candidates)} keys loaded.", "INFO")

    found = False

    # Iterate over each salt candidate
    for salt in salt_candidates:
        # Determine if the salt is in hexadecimal or base64 format
        if re.fullmatch(r"[a-fA-F0-9]+", salt):
            salt_mode = "hex"
        else:
            salt_mode = "b64"
        try:
            salt_bytes = candidate_to_bytes(salt, salt_mode)
        except Exception as e:
            log_message(f"Error converting salt candidate '{salt}': {str(e)}", "ERROR")
            continue

        # Iterate over each key candidate
        for key in key_candidates:
            # Determine if the key is in hexadecimal or base64 format
            if re.fullmatch(r"[0-9a-fA-F]+", key):
                key_mode = "hex"
                dklen = len(key) // 2  # every 2 hex characters represent one byte
            else:
                key_mode = "b64"
                try:
                    dklen = len(base64.b64decode(key + "==="))
                except Exception as e:
                    log_message(f"Error converting key candidate '{key}': {str(e)}", "ERROR")
                    continue

            # Compute the derived key using the selected algorithm
            try:
                derived = derive_key(salt_bytes, dklen)
            except Exception as e:
                log_message(f"Error computing derived key for salt '{salt}': {str(e)}", "ERROR")
                continue

            # Compare the computed derived key with the candidate key
            if key_mode == "hex":
                if derived.hex().lower() == key.lower():
                    print("\nMatch found using {}!".format(algorithm_used))
                    print(f"Master Password: {master_password}")
                    if algo_choice == "1":
                        print(f"Iteration Count: {iteration_count}")
                    else:
                        print(f"Time Cost (Iterations): {time_cost}")
                        print(f"Memory Cost (in MB): {memory_mb}")
                        print(f"Parallelism: {parallelism}")
                    print(f"Salt ({salt_mode}): {salt}")
                    print(f"Derived Key ({key_mode}): {key}")
                    log_message(f"Match found: Salt '{salt}' and Derived Key '{key}' using {algorithm_used}.", "INFO")
                    found = True
            else:
                computed_b64 = base64.b64encode(derived).decode("utf-8")
                if computed_b64 == key:
                    print("\nMatch found using {}!".format(algorithm_used))
                    print(f"Master Password: {master_password}")
                    if algo_choice == "1":
                        print(f"Iteration Count: {iteration_count}")
                    else:
                        print(f"Time Cost (Iterations): {time_cost}")
                        print(f"Memory Cost (in MB): {memory_mb}")
                        print(f"Parallelism: {parallelism}")
                    print(f"Salt ({salt_mode}): {salt}")
                    print(f"Derived Key ({key_mode}): {key}")
                    log_message(f"Match found: Salt '{salt}' and Derived Key '{key}' using {algorithm_used}.", "INFO")
                    found = True

    if not found:
        print("No matching salt and derived key pair was found using the provided parameters.")
        log_message(f"PM Brute Force Extended ({algorithm_used}): No matching pair found.", "INFO")
    else:
        print("PM Brute Force Extended analysis completed.")
        log_message(f"PM Brute Force Extended ({algorithm_used}): Analysis completed with at least one match.", "INFO")
# ======================================================================================
# MENU HANDLERS
# ======================================================================================

def handle_choice_1(txt_files: list) -> None:
    """
    Handler for Main Menu Option 1: Prompt the user to choose between
    searching with a literal string or a regex, then performs the search
    on all given txt_files.

    Args:
        txt_files (list): A list of text file paths to be searched.
    """
    search_type = input("Choose search type (1: string, 2: regex): ").strip()
    if search_type == "1":
        target = input("Enter search string: ").strip()
        if target:
            search_files(txt_files, target, False)
        else:
            print("Error: Input cannot be empty!")
    elif search_type == "2":
        target = input("Enter regex: ").strip()
        if target:
            try:
                re.compile(target)  # Validate regex
                search_files(txt_files, target, True)
            except re.error as e:
                print(f"Invalid regex: {str(e)}")
        else:
            print("Error: Input cannot be empty!")
    else:
        print("Invalid selection, please try again.")


def handle_choice_2(txt_files: list) -> None:
    """
    Handler for Main Menu Option 2: Asks the user for a password manager file,
    then calls search_from_password_manager_file to parse that file's search rules
    and search the provided txt_files accordingly.

    Args:
        txt_files (list): A list of text file paths to be searched.
    """
    password_file = input(
        "Enter password manager file path (e.g., /home/kali/Desktop/PM.txt, or 'exit' to return to main menu): "
    ).strip()
    if password_file.lower() == "exit":
        return
    if os.path.isfile(password_file):
        search_from_password_manager_file(txt_files, password_file)
    else:
        print(f"Error: File {password_file} does not exist!")


def handle_choice_3() -> None:
    """
    Handler for Main Menu Option 3: Simply calls view_log_file() to display
    the full contents of the log file.
    """
    view_log_file()


def view_log_file() -> None:
    """
    Displays the log file path and prints its contents if available.
    """
    try:
        print(f"\nLog file path: {log_file}\n")
        with open(log_file, "r", encoding="utf-8") as log:
            print(log.read())
    except FileNotFoundError:
        print(f"Log file {log_file} not found. Please ensure the log has been generated.")

# ======================================================================================
# MAIN FUNCTION
# ======================================================================================

def main() -> None:
    """
    Main function coordinating the entire tool:
    1) Checks dependencies ('strings', 'grep').
    2) Sets up logging.
    3) Prompts user for a directory with dump files.
    4) Lists and organizes the found files into two groups: .txt vs non-.txt.
    5) Offers to convert non-.txt files into .txt (via 'strings') if needed.
    6) Presents a menu with multiple options (search by string/regex, search via password file,
       view log, run PM Analysis, run PM Brute Force).
    7) Executes chosen options in a loop until user types 'exit'.
    """

    check_dump_dependencies()
    setup_log_file()

    print("\n===== Dump Analysis Tool =====")
    log_message("Program started", "INFO")

    # Prompt user for the directory containing potential dump files
    dump_directory = get_valid_directory(
        "\nEnter the directory containing dump files (e.g., /home/kali/Desktop/dumps_dcli, type 'exit' to quit): "
    )
    if not dump_directory:
        log_message("User exited the program", "INFO")
        print("\nProgram has exited.")
        return

    # List all files in the chosen directory
    all_files = list_files_in_directory(dump_directory)
    if not all_files:
        return

    # Separate .txt files from any others (potential dump files)
    dump_files = [f for f in all_files if not f.endswith(".txt")]
    txt_files = [f for f in all_files if f.endswith(".txt")]

    # If we only have .txt and no dump files
    if not dump_files and txt_files:
        print("\nOnly txt files were found in the directory.")
        choice = input("Do you want to proceed with these txt files for subsequent operations? (yes/no): ").strip().lower()
        if choice == "yes":
            log_message("User chose to proceed with existing txt files only.", "INFO")
        else:
            print("Program has exited.")
            log_message("User opted not to use existing txt files. Program exited.", "INFO")
            return
    elif not dump_files:
        # Means neither dump nor txt?
        print("No valid dump or txt files found. Exiting program.")
        return

    # If we do have dump files, check if any have already been converted
    if dump_files:
        already_converted = []
        not_converted = []
        for df in dump_files:
            txt_path = os.path.join(os.path.dirname(df), os.path.basename(df) + ".txt")
            if os.path.exists(txt_path):
                already_converted.append(df)
            else:
                not_converted.append(df)

        # Offer user choices regarding conversion
        if already_converted or not_converted:
            if already_converted and not_converted:
                print(
                    f"\nDetected that {len(already_converted)} dump files already have corresponding txt files, "
                    f"and {len(not_converted)} dump files do not."
                )
                conv_choice = input(
                    "Enter 'a' to convert all files (overwrite existing), "
                    "'b' to convert only those not converted, or 'c' to skip conversion "
                    "and use only existing txt files: "
                ).strip().lower()
                if conv_choice == "a":
                    print("Converting all dump files (overwriting existing ones)...")
                    log_message("User chose to convert all dump files (overwrite existing).", "INFO")
                    txt_files = convert_files(dump_files)
                elif conv_choice == "b":
                    print("Converting only dump files that have not been converted...")
                    log_message("User chose to convert only not converted dump files.", "INFO")
                    new_txt = convert_files(not_converted)
                    exist_txt = [
                        os.path.join(os.path.dirname(df), os.path.basename(df) + ".txt")
                        for df in already_converted
                    ]
                    txt_files = exist_txt + new_txt
                elif conv_choice == "c":
                    print("Skipping conversion; using only existing txt files (this may be incomplete).")
                    log_message("User chose to skip conversion; using only existing txt files.", "INFO")
                    txt_files = [
                        os.path.join(os.path.dirname(df), os.path.basename(df) + ".txt")
                        for df in dump_files
                        if os.path.exists(os.path.join(os.path.dirname(df), os.path.basename(df) + ".txt"))
                    ]
                else:
                    print("Invalid selection. Exiting program.")
                    log_message("User made an invalid selection on conversion prompt. Program exited.", "INFO")
                    return
            elif len(already_converted) == len(dump_files):
                conv_choice = input(
                    "\nAll dump files already have corresponding txt files.\n"
                    "Do you want to re-convert all dump files? (yes/no): "
                ).strip().lower()
                if conv_choice == "yes":
                    print("Re-converting all dump files (overwriting existing ones)...")
                    log_message("User chose to re-convert all dump files.", "INFO")
                    txt_files = convert_files(dump_files)
                else:
                    print("Using existing txt files.")
                    log_message("User chose to use existing txt files.", "INFO")
                    txt_files = [
                        os.path.join(os.path.dirname(df), os.path.basename(df) + ".txt")
                        for df in dump_files
                    ]
            else:
                # Means no .txt files exist at all
                conv_choice = input(
                    "\nNo txt files were detected.\nDo you want to convert dump files to txt files? (yes/no): "
                ).strip().lower()
                if conv_choice == "yes":
                    print("Converting all dump files...")
                    log_message("User chose to convert all dump files.", "INFO")
                    txt_files = convert_files(dump_files)
                else:
                    print("Program has exited.")
                    log_message("User opted not to convert dump files. Program exited.", "INFO")
                    return

    # If after potential conversion, we still have no text files, we can't proceed
    if not txt_files:
        print("No text files were generated. Exiting program.")
        return

    # ==================================================================================
    # MAIN MENU LOOP
    # ==================================================================================
    while True:
        print("\nMain Menu:")
        print("1. Use string/regex search")
        print("2. Use password manager file search")
        print("3. View log file")
        print("4. User login credentials Analysis")
        print("5. User login credentials Brute Force")
        print("exit")

        choice = input("Please select an option: ").strip()
        if choice == "1":
            handle_choice_1(txt_files)
        elif choice == "2":
            handle_choice_2(txt_files)
        elif choice == "3":
            handle_choice_3()
        elif choice == "4":
            # PM Analysis is run against the existing txt_files
            pm_analysis(txt_files)
        elif choice == "5":
            # PM Brute Force is run with user-provided master password + iteration count
            pm_bruteforce()
        elif choice.lower() == "exit":
            log_message(f"Program end time: {get_german_time()}", "INFO")
            print("Program has exited.")
            break
        else:
            print("Invalid selection, please try again.")


if __name__ == "__main__":
    main()
