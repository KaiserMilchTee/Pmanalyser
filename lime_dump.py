#!/usr/bin/env python3
import os
import sys
import subprocess
import shlex
import getpass
import time

def validate_sudo_password(sudo_pass: str) -> bool:
    """
    Validates the provided sudo password by executing 'sudo -S -v'.
    If the authentication succeeds, returns True; otherwise returns False.

    Rationale:
    - 'sudo -S' reads the password from standard input.
    - The '-v' option updates the user's cached credentials, validating the password
      without running a command that might have side effects.
    - If the provided password is incorrect, 'sudo -v' will fail with a non-zero exit code.
    """
    cmd = f"echo {shlex.quote(sudo_pass)} | sudo -S -v"
    try:
        subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def prompt_sudo_password() -> str:
    """
    Continuously prompts the user for their sudo password via getpass.getpass()
    until a correct password is entered. If the password is incorrect, the user is
    asked to try again.

    Returns:
        str: The correct sudo password.
    """
    while True:
        sudo_pass = getpass.getpass("Enter your sudo password: ").strip()
        if validate_sudo_password(sudo_pass):
            print("Sudo password is correct.")
            return sudo_pass
        else:
            print("Incorrect sudo password, please try again.")


def prompt_non_empty(prompt_text: str) -> str:
    """
    Prompts the user with 'prompt_text' until they enter a non-empty string.

    Args:
        prompt_text (str): The message shown to the user.

    Returns:
        str: The user's non-empty input.
    """
    while True:
        user_input = input(prompt_text).strip()
        if user_input:
            return user_input
        else:
            print("Input cannot be empty. Please try again.")


def prompt_directory(prompt_text: str) -> str:
    """
    Prompts the user for a directory path, handling two scenarios:
      1. If 'Desktop' or 'dump file' is in the prompt, it assumes this is an
         output directory and attempts to create it (if needed).
      2. Otherwise (for LiME folder), it checks if the directory exists and
         contains a 'src' subdirectory.

    Args:
        prompt_text (str): The message to display for the user input.

    Returns:
        str: A validated directory path.
    """
    while True:
        dir_input = input(prompt_text).strip()
        if not dir_input:
            print("Directory path cannot be empty. Please try again.")
            continue

        dir_input = os.path.expanduser(dir_input)
        if not os.path.isabs(dir_input):
            dir_input = os.path.abspath(os.path.join(os.path.expanduser("~"), dir_input))
            print(f"Converted to absolute path: {dir_input}")

        # Case 1: Output directory
        if "Desktop" in prompt_text or "dump file" in prompt_text:
            try:
                os.makedirs(dir_input, exist_ok=True)
                return dir_input
            except Exception as e:
                print(f"Unable to create directory '{dir_input}': {e}. Please try again.")
        else:
            # Case 2: LiME folder check (must have 'src' subdirectory)
            if os.path.isdir(dir_input):
                src_dir = os.path.join(dir_input, "src")
                if os.path.isdir(src_dir):
                    return dir_input
                else:
                    print(f"The folder '{dir_input}' does not contain a 'src' subdirectory. Please try again.")
            else:
                print(f"The directory '{dir_input}' does not exist. Please try again.")


def run_command(command: str, cwd: str = None) -> None:
    """
    Executes a shell command in the specified directory (if provided) and prints its output.
    If the command returns a non-zero exit code, the program terminates.

    Args:
        command (str): The shell command to run.
        cwd (str, optional): The working directory in which to run the command.

    Behavior:
        - Uses subprocess.run(...) with 'check=True', so an error triggers CalledProcessError.
        - Prints stdout/stderr if available.
        - Exits if the command fails.
    """
    print(f"Executing: {command}")
    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        if result.stdout:
            print(result.stdout.strip())
        if result.stderr:
            print(result.stderr.strip())
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e.stderr.strip()}")
        sys.exit(1)


def remove_module(sudo_pass: str) -> None:
    """
    Attempts to remove the 'lime' kernel module using 'rmmod lime' with sudo privileges.
    If the module is not loaded, prints "No module loaded." and continues.

    Args:
        sudo_pass (str): The validated sudo password.
    """
    cmd = f"echo {shlex.quote(sudo_pass)} | sudo -S rmmod lime"
    print("Removing LiME module...")
    result = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    if result.returncode == 0:
        print("Module removed successfully.")
    else:
        if "Module lime is not currently loaded" in result.stderr:
            print("No module loaded.")
        else:
            print(f"Error removing module: {result.stderr.strip()}")


def insert_module(sudo_pass: str, module_filepath: str, param: str) -> None:
    """
    Inserts the LiME kernel module using the full module filepath.

    Args:
        sudo_pass (str): Sudo password.
        module_filepath (str): Full path to the LiME module (e.g., /home/kali/LiME/src/lime-6.10.9-amd64.ko).
        param (str): Module parameters.
    """
    cmd = f"echo {shlex.quote(sudo_pass)} | sudo -S insmod {shlex.quote(module_filepath)} {shlex.quote(param)}"
    print("Inserting LiME module to generate dump...")
    run_command(cmd)


def set_file_permissions_sudo(sudo_pass: str, file_path: str, mode: str = "666") -> None:
    """
    Uses sudo to change the file permissions (chmod) of the generated dump file.

    Args:
        sudo_pass (str): The validated sudo password.
        file_path (str): The file whose permissions should be modified.
        mode (str, optional): The desired permissions mode, default is "666" (rw-rw-rw-).
    """
    cmd = f"echo {shlex.quote(sudo_pass)} | sudo -S chmod {mode} {shlex.quote(file_path)}"
    print(f"Setting file permissions for '{file_path}' to {mode} using sudo...")
    run_command(cmd)


def main() -> None:
    """
    Main function to generate a memory dump using the LiME (Linux Memory Extractor) kernel module.

    Workflow Outline:
    1) Prompt the user for their sudo password, verifying it via 'sudo -S -v'.
    2) Ask the user for a desired dump file name.
    3) Ask the user for the output directory where the dump file will be saved (create if needed).
    4) Ask for the LiME folder location, which must contain a 'src' subdirectory.
    5) Identify and remove any previously loaded LiME module.
    6) Build a suitable LiME module file name based on the current kernel version or use 'lime.ko' fallback.
    7) Insert the LiME module with parameters to write the dump file as 'format=lime'.
    8) Wait briefly, then check if the dump file is created.
    9) Change the dump file's permissions to be readable/writable by all (666).
    10) Remove the LiME module again for clean-up.

    This script assumes:
    - The user can compile the LiME module for their kernel version in the <lime_folder>/src directory.
    - The user has the required privileges to run 'insmod' and 'rmmod' via sudo.

    If any step fails, the script reports an error and may exit.
    """

    print("LiME Memory Dump Generator")

    # 1) Prompt for sudo password until valid
    sudo_pass = prompt_sudo_password()

    # 2) Get the desired dump file name
    dump_name = prompt_non_empty("Enter the desired dump file name (e.g., dump.lime): ")

    # 3) Get the output directory, creating if needed
    output_dir = prompt_directory("Enter the output directory for the dump file: ")

    # 4) Get the LiME folder location, must contain a 'src' subdirectory
    lime_folder = prompt_directory("Enter the LiME folder location (e.g., /home/user/LiME): ")

    # Construct the full dump file path
    dump_filepath = os.path.join(output_dir, dump_name)

    # Acquire the current kernel version
    kernel_version = os.uname().release
    print(f"Detected kernel version: {kernel_version}")

    # Build the module parameter for LiME insmod
    param = f"path={dump_filepath} format=lime"
    print(f"Using parameter: {param}")

    # 5) Remove any previously loaded LiME module
    remove_module(sudo_pass)

    # 6) Identify the LiME 'src' directory and the expected module filename
    src_dir = os.path.join(lime_folder, "src")
    if not os.path.isdir(src_dir):
        print(f"Error: The src directory '{src_dir}' does not exist.")
        sys.exit(1)

    module_filename = f"lime-{kernel_version}.ko"
    module_filepath = os.path.join(src_dir, module_filename)
    if not os.path.isfile(module_filepath):
        # If not found, try fallback
        fallback_filepath = os.path.join(src_dir, "lime.ko")
        if os.path.isfile(fallback_filepath):
            module_filepath = fallback_filepath
            print("Using fallback module file: lime.ko")
        else:
            print(f"Error: LiME kernel module not found at {module_filepath} or fallback at {fallback_filepath}.")
            sys.exit(1)

    # Insert the module using the full path.
    insert_module(sudo_pass, module_filepath, param)

    # 8) Wait briefly to let the dump file creation progress
    time.sleep(2)

    # 9) Check if the dump file was successfully generated
    if os.path.isfile(dump_filepath):
        print(f"Dump file generated successfully at: {dump_filepath}")
        # Change permissions to allow read/write for all (666)
        set_file_permissions_sudo(sudo_pass, dump_filepath, "666")
    else:
        print("Failed to generate dump file. Please check your configuration and try again.")
        sys.exit(1)

    # 10) Remove the LiME module again
    remove_module(sudo_pass)


if __name__ == "__main__":
    main()
