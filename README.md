# Linux Privilege Escalation Script

This script is designed to assist in the detection of possible misconfigurations that may lead to privilege escalation on a Linux system. 
I use this as a "first view" script to gather basic system config information and detect "easy win" vulnerabilities - it is not intended to replace more comprehensive tools, such as LinPEAS.
It provides a quick overview of system information, user and group details, file permissions, network configurations, running processes, scheduled tasks, and potential security issues.

## Usage

Run the script on a Linux system with the following command:

```bash
bash privilege-escalation.sh
```
# Features
- System Information: Displays details such as hostname, system architecture, kernel information, and release information.
- Useful Tools: Checks for the availability of essential tools such as Python, Perl, Ruby, GCC, and tcpdump.
- Users + Groups: Provides information about user accounts, group memberships, and sudo configuration.
- Files + Permissions: Examines file and directory permissions, searching for sensitive files and world-writable files.
- Networking: Reports network and IP information, DNS settings, and listening ports.
- Running Processes: Lists all running processes and identifies processes running with root privileges.
- Tasks & Cron: Displays cron jobs, systemd timers, and scheduled tasks.
- Possible Credentials: Searches for potential credentials, including private SSH keys.
- Easy Wins: Identifies common binaries and executables that may have security implications.

# Disclaimer
This script is meant for educational and authorised auditing purposes only (eg. HackTheBox)
