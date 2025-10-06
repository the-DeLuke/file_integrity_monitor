import os
import hashlib
import json
import time
from datetime import datetime

# The default name for the file that stores the baseline hashes.
BASELINE_FILENAME = "baseline.json"

def calculate_sha256(filepath):
    """
    Calculates the SHA-256 hash of a given file.
    
    Args:
        filepath (str): The path to the file.
        
    Returns:
        str: The hexadecimal SHA-256 hash of the file, or None if the file cannot be read.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read the file in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError as e:
        print(f"Error reading file {filepath}: {e}")
        return None

def create_baseline(directory):
    """
    Creates a baseline of file hashes for all files in a directory.
    
    Args:
        directory (str): The path to the directory to scan.
    """
    baseline = {}
    print(f"Creating a new baseline for the directory: {directory}")
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            # Skip the baseline file itself
            if os.path.basename(filepath) == BASELINE_FILENAME:
                continue
            
            file_hash = calculate_sha256(filepath)
            if file_hash:
                baseline[filepath] = file_hash
    
    try:
        with open(BASELINE_FILENAME, "w") as f:
            json.dump(baseline, f, indent=4)
        print(f"Baseline created successfully and saved to '{BASELINE_FILENAME}'")
    except IOError as e:
        print(f"Error writing baseline file: {e}")

def check_integrity(directory):
    """
    Checks the integrity of files in a directory against the saved baseline.
    This version uses a more robust set-based comparison for a one-time check.
    """
    try:
        with open(BASELINE_FILENAME, "r") as f:
            baseline = json.load(f)
    except FileNotFoundError:
        print(f"Error: Baseline file '{BASELINE_FILENAME}' not found.")
        print("Please create a baseline first by running with the --create flag.")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not decode the baseline file '{BASELINE_FILENAME}'. It might be corrupted.")
        return

    # Scan the directory to get the current state of files
    current_files = {}
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if os.path.basename(filepath) == BASELINE_FILENAME:
                continue
            
            file_hash = calculate_sha256(filepath)
            if file_hash:
                current_files[filepath] = file_hash

    # --- Use set operations for a clearer and more robust comparison ---
    baseline_paths = set(baseline.keys())
    current_paths = set(current_files.keys())

    added_files = current_paths - baseline_paths
    deleted_files = baseline_paths - current_paths
    common_files = baseline_paths.intersection(current_paths)

    changes_found = False

    # Report added files
    for filepath in added_files:
        print(f"ALERT: New file added! -> {filepath}")
        changes_found = True

    # Report deleted files
    for filepath in deleted_files:
        print(f"ALERT: File deleted! -> {filepath}")
        changes_found = True

    # Report modified files
    for filepath in common_files:
        if baseline[filepath] != current_files[filepath]:
            print(f"ALERT: File modified! -> {filepath}")
            print(f"  - Expected hash: {baseline[filepath]}")
            print(f"  - Current hash:  {current_files[filepath]}")
            changes_found = True

    if not changes_found:
        print("No changes detected.")
    
    print("Integrity check complete.")


def monitor_directory(directory, interval):
    """
    Continuously monitors a directory for changes at a specified interval.
    This version keeps the baseline in memory and updates it after each check.
    """
    print(f"Starting continuous monitoring of '{directory}' every {interval} seconds. Press Ctrl+C to stop.")
    
    # Load the initial baseline from the file into memory
    try:
        with open(BASELINE_FILENAME, "r") as f:
            baseline = json.load(f)
        print("Baseline loaded. Starting monitor...")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading baseline file: {e}")
        print("Please create a valid baseline first using the --create flag.")
        return

    # Start the monitoring loop
    while True:
        try:
            print("-" * 60)
            print(f"Running check at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            # Get the current state of the directory
            current_files = {}
            for dirpath, _, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.basename(filepath) == BASELINE_FILENAME:
                        continue
                    file_hash = calculate_sha256(filepath)
                    if file_hash:
                        current_files[filepath] = file_hash

            # Compare the current state with the in-memory baseline
            baseline_paths = set(baseline.keys())
            current_paths = set(current_files.keys())

            added_files = current_paths - baseline_paths
            deleted_files = baseline_paths - current_paths
            common_files = baseline_paths.intersection(current_paths)

            changes_found = False

            # Report and process added files
            for filepath in added_files:
                print(f"ALERT: New file added! -> {filepath}")
                baseline[filepath] = current_files[filepath]  # Add to in-memory baseline
                changes_found = True

            # Report and process deleted files
            for filepath in deleted_files:
                print(f"ALERT: File deleted! -> {filepath}")
                del baseline[filepath]  # Remove from in-memory baseline
                changes_found = True

            # Report and process modified files
            for filepath in common_files:
                if baseline[filepath] != current_files[filepath]:
                    print(f"ALERT: File modified! -> {filepath}")
                    print(f"  - Old hash: {baseline[filepath]}")
                    print(f"  - New hash: {current_files[filepath]}")
                    baseline[filepath] = current_files[filepath]  # Update in-memory baseline
                    changes_found = True

            if not changes_found:
                print("No changes detected.")
            
            print("Integrity check complete.")
            print("-" * 60)
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            time.sleep(interval)


def main():
    """
    Main function to parse command-line arguments and run the tool.
    """
    import argparse
    parser = argparse.ArgumentParser(description="File Integrity Monitor using SHA-256 hashes.")
    parser.add_argument("directory", help="The directory to monitor.")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--create", action="store_true", help="Create a new baseline for the directory.")
    group.add_argument("--check", action="store_true", help="Perform a one-time integrity check against the baseline.")
    group.add_argument("--monitor", type=int, metavar="SECONDS", help="Continuously monitor the directory at the specified interval (in seconds).")

    args = parser.parse_args()

    # Ensure the provided path is a valid directory
    if not os.path.isdir(args.directory):
        print(f"Error: The provided path '{args.directory}' is not a valid directory.")
        return

    if args.create:
        create_baseline(args.directory)
    elif args.check:
        check_integrity(args.directory)
    elif args.monitor:
        monitor_directory(args.directory, args.monitor)

if __name__ == "__main__":
    main()

