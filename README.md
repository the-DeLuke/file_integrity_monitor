File Integrity Monitor
This script is a command-line tool designed to monitor a directory for any changes to its files. It works by creating a "baseline" record of SHA-256 hashes for every file and then comparing the current state of the files against that baseline to detect any modifications, additions, or deletions.

How to Run the Script
You must run this script from a terminal or command prompt. Make sure you are in the same directory where the file_monitor.py script is located.

1. Creating a Baseline
Before you can check for changes, you must first create a baseline. This command scans your target folder and saves the hash of every file into a baseline.json file.

Command:

python file_monitor.py "<your-folder-path>" --create

Example for your specific folder:

python file_monitor.py "D:\Entertainment\Series\Korean\S\FIM" --create

2. Performing a One-Time Check
This command will scan the target folder and compare its current state to the last saved baseline. It will report any files that have been created, deleted, or modified since the baseline was made.

Command:

python file_monitor.py "<your-folder-path>" --check

Example for your specific folder:

python file_monitor.py "D:\Entertainment\Series\Korean\S\FIM" --check

3. Continuously Monitoring a Directory
This command will run an integrity check on a continuous loop, checking for changes at an interval you specify (in seconds). This is useful for real-time security monitoring. Press Ctrl+C to stop the monitor.

Command:

python file_monitor.py "<your-folder-path>" --monitor <seconds>

Example for your specific folder (checking every 30 seconds):

python file_monitor.py "D:\Entertainment\Series\Korean\S\FIM" --monitor 30
