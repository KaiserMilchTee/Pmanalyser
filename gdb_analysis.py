#!/usr/bin/env python3
import os
import re
import sys
import subprocess
import tempfile
import shlex
import threading
import shutil
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor

# ======================================================================================
# GLOBAL DEFINITIONS
# ======================================================================================

# This is the user's desktop path, used as the default location for saving logs.
desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")

# The log file will be stored on the user's desktop.
log_file = os.path.join(desktop_path, "ptrace_analysis_log.txt")

# A threading lock used for writing to the log file in a thread-safe manner.
log_lock = threading.Lock()

# ======================================================================================
# DEPENDENCY CHECK & INITIAL SETUP
# ======================================================================================

def check_dependencies() -> None:
    """
    Verifies the presence of essential external commands in the system. Specifically checks:
      - gdb: GDB debugger, used to attach to processes and inspect memory.
      - gcore: GDB-based utility for generating core dumps of running processes.
      - ps: Used to list processes (ps -ef).

    If any command is missing, prints an error message and exits the program.
    """
    required_commands = ['gdb', 'gcore', 'ps']
    missing = []
    for cmd in required_commands:
        if not shutil.which(cmd):
            missing.append(cmd)
    if missing:
        print(
            f"Error: The following required commands are missing: {', '.join(missing)}. "
            "Please install them and try again."
        )
        sys.exit(1)

def get_german_time() -> str:
    """
    Returns a string representing the current time in Germany (Europe/Berlin) in the format YYYY-MM-DD HH:MM:SS,
    used for consistent timestamp logging.
    """
    tz = pytz.timezone("Europe/Berlin")
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")

def setup_log_file() -> None:
    """
    Ensures the user's desktop directory exists and appends a separator plus a 'Log Start' line
    with the current German timestamp to the global log file. This is typically called once
    at program start.
    """
    os.makedirs(desktop_path, exist_ok=True)
    with open(log_file, "a") as log:
        log.write("\n=========\n")
        log.write(f"Log Start: {get_german_time()}\n")

def log_message(message: str, level: str = "INFO") -> None:
    """
    Appends a log message to the global log file in a thread-safe manner.

    Args:
        message (str): The content of the log entry.
        level (str): The log level (e.g., INFO, WARNING, ERROR).
    """
    with log_lock:
        with open(log_file, "a") as log:
            timestamp = get_german_time()
            log.write(f"[{timestamp} - {level}] {message}\n")

# ======================================================================================
# DIRECTORY & FILE UTILITIES
# ======================================================================================

def get_valid_directory(prompt: str) -> str:
    """
    Continuously prompts the user for a directory path until a valid directory is provided
    or until the user types 'exit'. If 'exit' is typed, returns None.

    Args:
        prompt (str): The message prompting the user for input.

    Returns:
        str: A valid directory path, or None if user chooses to exit.
    """
    while True:
        path = input(prompt).strip()
        if path.lower() == 'exit':
            return None
        if os.path.isdir(path):
            return path
        print(f"Error: The path '{path}' does not exist or is not a directory!")
        log_message(f"Invalid directory input: {path}", "WARNING")

def list_files_in_directory(directory: str) -> list:
    """
    Attempts to list all files in the specified directory. Logs warnings or errors
    if any issues are encountered (e.g., permission denied, directory not found).

    Args:
        directory (str): The directory path to scan.

    Returns:
        list: A list of absolute paths to files in the directory. May be empty if no files or an error occurs.
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
            log_message(f"Files in directory {directory}: {files}")
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
# PROGRAM DESCRIPTION & PTRACE SCOPE CHECK
# ======================================================================================

def display_program_info() -> None:
    """
    Displays a brief introduction to the program, outlining that it
    attaches to processes for memory analysis using GDB (pwndbg),
    possibly generating memory dumps, etc.
    """
    print("""
    The goal of this program is to analyze password manager process memory
    using the GDB pwndbg plugin under non-root user permissions with ptrace enabled.
    It also supports memory dumping.

    Currently, it supports password managers like Keeper, which can be used
    to analyze specific user credentials under option 2 (matching files with a specific password manager).

    Note:
     - Due to current limitations of the pwndbg plugin, regular expression analysis is not supported.
     - Ensure that ptrace is allowed in system settings; otherwise the program will not function.
    """)

def check_ptrace_scope() -> bool:
    """
    Checks whether the ptrace_scope setting (/proc/sys/kernel/yama/ptrace_scope) is 0,
    which allows non-root process debugging. If not 0, warns the user to adjust the setting.

    Returns:
        bool: True if ptrace is likely allowed, False if the setting or file is missing.
    """
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope", "r") as f:
            scope_setting = int(f.read().strip())
        if scope_setting != 0:
            warning_message = (
                "Warning: The current ptrace_scope setting may prevent non-root users from debugging processes.\n"
                "Please run the following command to lower the ptrace_scope setting and restart the script:\n"
                "  echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope"
            )
            print(warning_message)
            log_message(warning_message, "WARNING")
            return False
        return True
    except FileNotFoundError:
        warning_message = ("Unable to access ptrace_scope setting. The system may not support it, "
                           "or the file may not exist.")
        print(warning_message)
        log_message(warning_message, "WARNING")
        return False

# ======================================================================================
# GDB COMMAND HELPERS
# ======================================================================================
def run_gdb_commands(commands: list) -> str:
    """
    Executes a sequence of GDB commands by writing them to a temporary file and running
    'gdb -q -batch -x <temp_file>'. Captures the stdout on success, or logs errors on failure.

    If the output or stderr contains "ptrace: Operation not permitted", the function logs the error
    and terminates the program.

    Args:
        commands (list): A list of GDB commands like ["attach 1234", "search myString", "detach", "quit"].

    Returns:
        str: The combined stdout of the GDB session, or an empty string if GDB fails.
    """
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("\n".join(commands))
        temp_file_name = f.name
    try:
        result = subprocess.check_output(
            ["gdb", "-q", "-batch", "-x", temp_file_name],
            text=True,
            stderr=subprocess.PIPE
        )
        # 如果输出中包含 ptrace 错误，则记录并终止程序
        if "ptrace: Operation not permitted" in result:
            final_message = (
                "Error: ptrace is not permitted. Please check your system settings or adjust ptrace_scope "
                "(e.g., echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope)"
            )
            print(final_message)
            log_message(final_message, "ERROR")
            sys.exit(1)
        return result
    except subprocess.CalledProcessError as e:
        error_message = f"GDB execution failed: {e}\nStderr: {e.stderr}"
        print(error_message)
        log_message(error_message, "ERROR")
        if "ptrace: Operation not permitted" in e.stderr:
            final_message = (
                "Error: ptrace is not permitted. Please check your system settings or adjust ptrace_scope "
                "(e.g., echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope)"
            )
            print(final_message)
            log_message(final_message, "ERROR")
            sys.exit(1)
        return ""
    finally:
        os.unlink(temp_file_name)



# ======================================================================================
# PROCESS HANDLING
# ======================================================================================

def is_pid_valid(pid: str) -> bool:
    """
    Checks if the given PID exists by verifying the presence of the /proc/<pid> directory.

    Args:
        pid (str): The process ID in string form.

    Returns:
        bool: True if the process directory exists; else False.
    """
    return os.path.exists(f"/proc/{pid}")

def get_process_ids_by_name(process_name: str) -> list:
    """
    Retrieves a list of PIDs that match the given process name or substring by running 'ps -ef'
    and filtering with 'grep <process_name>'. Returns a list of matching PIDs.

    Args:
        process_name (str): The name (or partial name) of the target process(es).

    Returns:
        list: A list of PIDs (strings) that match the provided name.
    """
    try:
        ps = subprocess.Popen(["ps", "-ef"], stdout=subprocess.PIPE)
        grep = subprocess.Popen(
            ["grep", process_name],
            stdin=ps.stdout,
            stdout=subprocess.PIPE
        )
        ps.stdout.close()
        output, _ = grep.communicate()
        decoded = output.decode().strip()
        return [
            line.split()[1]
            for line in decoded.split("\n")
            if line and process_name in line and "grep" not in line
        ]
    except Exception as e:
        error_message = f"PID fetch failed for {process_name}: {e}"
        print(error_message)
        log_message(error_message, "ERROR")
        return []

# ======================================================================================
# MEMORY ANALYSIS
# ======================================================================================

def validate_hex_address(address: str) -> bool:
    """
    Validates that 'address' is a proper hexadecimal address format, e.g. 0x7ffff7dd7000.

    Args:
        address (str): The address string to validate.

    Returns:
        bool: True if it matches "^0x[0-9a-fA-F]+$", else False.
    """
    return re.match(r"^0x[0-9a-fA-F]+$", address) is not None

def attach_and_search(pid: str, pattern: str) -> list:
    """
    Attaches to a process via GDB, searches memory for a specific pattern using 'search <pattern>',
    then detaches.

    Args:
        pid (str): The target process ID to attach to.
        pattern (str): The string/pattern to search in the process memory.

    Returns:
        list: A list of lines from GDB output that contain "0x" addresses and match the pattern.
    """
    commands = [
        f"attach {pid}",
        f"search {pattern}",
        "detach",
        "quit"
    ]
    result = run_gdb_commands(commands)

    # Extract lines that contain "0x" (addresses) and also contain our pattern.
    matches = [line.strip() for line in result.splitlines() if "0x" in line]
    valid_matches = [match for match in matches if pattern in match]
    return valid_matches

def inspect_memory_address(pid: str, address: str) -> str:
    """
    Uses GDB to inspect a single memory address via 'x/s <address>' after attaching to the process.

    Args:
        pid (str): Target process ID.
        address (str): A valid 0x-based memory address.

    Returns:
        str: The content at that address, or an empty string if not found.
    """
    commands = [
        f"attach {pid}",
        f"x/s {address}",
        "detach",
        "quit"
    ]
    result = run_gdb_commands(commands)
    for line in result.splitlines():
        if line.startswith(address):
            # The memory content should appear after the address
            return line.split(maxsplit=1)[-1].strip()
    return ""

def analyze_all_memory(pids: list, specific_string: str = None) -> None:
    """
    Concurrently attaches to each PID in 'pids' and searches the memory for 'specific_string',
    if provided. If no string is provided, it simply does not perform a memory search.

    Args:
        pids (list): The process IDs to analyze.
        specific_string (str, optional): The pattern/string to search for.
    """

    def _analyze_single(pid: str) -> list:
        try:
            return attach_and_search(pid, specific_string) if specific_string else []
        except Exception as ex:
            error_msg = f"Exception while analyzing memory of PID {pid}: {ex}"
            print(error_msg)
            log_message(error_msg, "ERROR")
            return []

    with ThreadPoolExecutor() as executor:
        results = executor.map(_analyze_single, pids)
        for pid, matches in zip(pids, results):
            print(f"Analyzing memory of process {pid}...")
            log_message(f"Analyzing memory of process {pid}...")
            if matches:
                print(f"Valid matches (Process {pid}):")
                log_message(f"Valid matches (Process {pid}):")
                for match in matches:
                    print(f"  {match}")
                    log_message(f"  {match}")
                    parts = match.split()
                    if len(parts) > 1 and parts[1].startswith("0x"):
                        memory_address = parts[1]
                        try:
                            full_content = inspect_memory_address(pid, memory_address)
                            if full_content:
                                print(f"  Full content: {full_content}")
                                log_message(f"  Full content: {full_content}")
                        except Exception as ex:
                            error_msg = f"Error inspecting memory at {memory_address} for PID {pid}: {ex}"
                            print(error_msg)
                            log_message(error_msg, "ERROR")
            else:
                print(f"No matches found for process {pid}.")

def analyze_with_password_manager_file(pids: list, manager_file: str) -> None:
    """
    Reads each non-empty line of 'manager_file' as a pattern to search in each PID's memory.

    Args:
        pids (list): The process IDs to analyze.
        manager_file (str): File path containing patterns, one per line.
    """
    if not os.path.exists(manager_file):
        print(f"Specified file {manager_file} does not exist.")
        log_message(f"Specified file {manager_file} does not exist.", "ERROR")
        return

    with open(manager_file, "r") as f:
        patterns = [line.strip() for line in f if line.strip()]

    for pattern in patterns:
        print(f"Matching pattern '{pattern}'...")
        log_message(f"Matching pattern '{pattern}':")
        analyze_all_memory(pids, specific_string=pattern)

# ======================================================================================
# USER INTERACTIONS (PID SELECTION, MEMORY VIEW, ETC.)
# ======================================================================================

def get_valid_pid_from_user(pids: list) -> str:
    """
    Prompts the user to select a valid PID from the given list of pids.

    Args:
        pids (list): The process IDs that are potentially valid.

    Returns:
        str: The selected PID, or None if 'exit' is typed.
    """
    valid_pids = [pid for pid in pids if is_pid_valid(pid)]
    while True:
        user_input = input(f"Enter PID from {valid_pids} (type 'exit' to quit): ").strip()
        if user_input.lower() == "exit":
            print("Exited memory viewing operation.")
            return None
        if user_input in valid_pids:
            return user_input
        print("Error: Invalid PID. Choose from active processes.")

def view_memory_address(pids: list, address: str, num_lines: str) -> None:
    """
    Views memory content at 'address' in one chosen PID, attempting to dump 'num_lines' lines via GDB.

    Args:
        pids (list): The process IDs available.
        address (str): A 0x-based memory address.
        num_lines (str): How many lines to display, must be a positive integer.
    """
    if not validate_hex_address(address):
        print("Error: Invalid address format.")
        return

    try:
        lines = int(num_lines)
        # Cap lines at some reasonable number to prevent spamming
        lines = min(lines, 1000)
    except ValueError:
        print("Error: Invalid line count.")
        return

    pid = get_valid_pid_from_user(pids)
    if not pid:
        return

    # We assume the user has the hexdump command from pwndbg or a similar plugin
    commands = [
        f"attach {pid}",
        f"hexdump {address} {lines}",
        "detach",
        "quit"
    ]
    result = run_gdb_commands(commands)
    valid_lines = [line for line in result.splitlines() if line.startswith("+")]
    if valid_lines:
        print(f"Memory content (PID {pid}):")
        for line in valid_lines:
            print(line)
            log_message(line)
    else:
        print("No readable content found.")

# ======================================================================================
# MEMORY DUMP (gcore)
# ======================================================================================

def generate_memory_dump_with_gcore(pids: list, output_dir: str) -> None:
    """
    Generates core dump files for each process in 'pids' using 'gcore'. By default,
    we cap the number of dumps at 20 to avoid generating excessive amounts of data.

    Args:
        pids (list): List of process IDs to dump.
        output_dir (str): Path where the generated .core files are saved.
    """
    MAX_DUMPS = 20
    if len(pids) > MAX_DUMPS:
        print(f"Warning: Truncated to first {MAX_DUMPS} processes.")
        pids = pids[:MAX_DUMPS]

    # Ensure output directory exists
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    for pid in pids:
        dump_path = os.path.join(output_dir, f"process_{pid}.core")
        try:
            subprocess.run(
                ["gcore", "-o", dump_path, pid],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
            print(f"Dump generated: {dump_path}")
            log_message(f"Dump generated: {dump_path}")
        except subprocess.CalledProcessError as e:
            error = f"gcore failed for PID {pid}: {e.stderr.decode().strip()}"
            print(error)
            log_message(error, "ERROR")

def print_log_file_location() -> None:
    """
    Prints the location of the log file on the desktop, for user reference.
    """
    print(f"Log file is saved on the desktop: {log_file}")

# ======================================================================================
# MENU CHOICE HANDLERS
# ======================================================================================

def handle_choice_1(pids: list) -> None:
    """
    Handles user choice 1: Enter a specific string to search in the memory
    of each PID in 'pids'.

    Args:
        pids (list): The list of valid process IDs.
    """
    specific_string = input("Enter search string (type 'exit' to quit): ").strip()
    if specific_string.lower() == "exit":
        print("Exited string search.")
        return

    analyze_all_memory(pids, specific_string)

    # Optionally, let the user view memory context around any matched address
    while True:
        choice = input("View memory context? (y/n): ").lower().strip()
        if choice == "y":
            address = input("Enter address (e.g., 0x7ffff7dd7000): ").strip()
            if not validate_hex_address(address):
                print("Error: Invalid address format.")
                continue
            lines = input("Lines to display (e.g., 10): ").strip()
            if not lines.isdigit() or int(lines) <= 0:
                print("Error: Positive integer required.")
                continue
            view_memory_address(pids, address, lines)
        elif choice == "n":
            break

def handle_choice_2(pids: list) -> None:
    """
    Handles user choice 2: Analyze memory using patterns from a password manager file.

    Args:
        pids (list): The list of valid process IDs.
    """
    print("Currently known password managers include: Keeper")
    manager_file = input(
        "Enter the file path (e.g., '/home/kali/Desktop/keeper.txt', type 'exit' to quit): "
    ).strip()
    if manager_file.lower() == "exit":
        print("Exited password manager matching operation.")
        return

    analyze_with_password_manager_file(pids, manager_file)

    if input("Do you want to view memory address context? (y/n): ").strip().lower() == "y":
        address = input("Enter memory address (e.g., 0x7ffff7dd7000, type 'exit' to quit): ").strip()
        if address.lower() == "exit":
            print("Exited memory address viewing operation.")
            return
        num_lines = input("Enter the number of lines to display (e.g., 10, type 'exit' to quit): ").strip()
        if num_lines.lower() == "exit":
            print("Exited memory address viewing operation.")
            return
        view_memory_address(pids, address, num_lines)

def handle_choice_3(pids: list) -> None:
    """
    Handles user choice 3: Direct memory address viewing without a search.
    Prompts for an address and the number of lines to display, then calls view_memory_address().

    Args:
        pids (list): The list of valid process IDs.
    """
    address = input("Enter memory address (e.g., 0x7ffff7dd7000, type 'exit' to quit): ").strip()
    if address.lower() == "exit":
        print("Exited memory address viewing operation.")
        return
    num_lines = input("Enter the number of lines to display (e.g., 50, type 'exit' to quit): ").strip()
    if num_lines.lower() == "exit":
        print("Exited memory address viewing operation.")
        return
    view_memory_address(pids, address, num_lines)

def handle_choice_4(pids: list) -> None:
    """
    Handles user choice 4: Generate a memory dump using gcore for the given list of PIDs.

    Args:
        pids (list): The list of valid process IDs.
    """
    # Prompt the user for an output directory path
    output_directory = get_valid_directory(
        "Enter directory path to save dump (e.g., '/home/kali/Desktop/dumps', type 'exit' to quit): "
    )
    if not output_directory:
        print("Exited memory dump generation.")
        return
    generate_memory_dump_with_gcore(pids, output_directory)

def handle_choice_5() -> None:
    """
    Handles user choice 5: Displays the contents of the global log file, if present.
    """
    try:
        print(f"\nLog file path: {log_file}\n")
        print("Log file contents:\n")
        with open(log_file, "r") as log:
            print(log.read())
    except FileNotFoundError:
        print(f"Log file {log_file} not found. Ensure the program has generated it.")

# ======================================================================================
# MAIN FUNCTION / MENU
# ======================================================================================

def main() -> None:
    """
    Main function orchestrating the ptrace-based memory analysis tool. The workflow is:
      1) Display program info and set up logging.
      2) Check that the required commands (gdb, gcore, ps) are installed.
      3) Confirm ptrace_scope allows non-root debugging.
      4) Prompt the user for a process name or partial name to gather matching PIDs.
      5) Present a menu with options to search memory, use a password manager file,
         view memory addresses, generate dumps, or view logs.
      6) Execute user choices until 'exit'.

    If the user tries to search memory while ptrace is disallowed or dependencies are missing,
    the script will exit with an error message.
    """
    # Display info and prepare logging
    display_program_info()
    setup_log_file()

    # Ensure we have gdb, gcore, and ps
    check_dependencies()

    # Ensure ptrace is allowed
    if not check_ptrace_scope():
        sys.exit(1)

    # Ask the user for the process name / partial name
    process_name = input("Enter target process name or partial name: ").strip()
    pids = get_process_ids_by_name(process_name)
    if not pids:
        print("No matching processes found.")
        return

    print(f"Found the following process PIDs: {', '.join(pids)}")

    # Menu loop
    while True:
        print("\nMain Menu:")
        print("1. Enter a specific string to search")
        print("2. Use a specific password manager file for matching")
        print("3. View memory address context")
        print("4. Generate memory dump file")
        print("5. View log file")
        print("exit")

        choice = input("Please select an option: ").strip()
        if choice == "1":
            handle_choice_1(pids)
        elif choice == "2":
            handle_choice_2(pids)
        elif choice == "3":
            handle_choice_3(pids)
        elif choice == "4":
            handle_choice_4(pids)
        elif choice == "5":
            handle_choice_5()
        elif choice.lower() == "exit":
            log_message(f"Program end time: {get_german_time()}")
            print("Program has exited.")
            break
        else:
            print("Invalid selection, please try again.")


if __name__ == "__main__":
    main()
select an option: ").strip()
        if choice == "1":
            handle_choice_1(pids)
        elif choice == "2":
            handle_choice_2(pids)
        elif choice == "3":
            handle_choice_3(pids)
        elif choice == "4":
            handle_choice_4(pids)
        elif choice == "5":
            handle_choice_5()
        elif choice.lower() == "exit":
            log_message(f"Program end time: {get_german_time()}")
            print("Program has exited.")
            break
        else:
            print("Invalid selection, please try again.")


if __name__ == "__main__":
    main()
