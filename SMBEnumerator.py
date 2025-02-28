#!/usr/bin/env python3
import sys
import argparse
import datetime
import json
import shlex
import subprocess
from time import sleep
from threading import Thread, active_count
from ipparser import ipparser

class SMBEnumerator:
    known_users = ['Administrator', 'Guest', 'krbtgt', 'root', 'bin']
    domain_sid = ""
    acquired_users = []
    results = {}

    def __init__(self, target, username=None, password=None, verbose=False):
        self.target = target
        self.username = username
        self.password = password
        self.verbose = verbose
        self.results = {"users": [], "shares": [], "groups": [], "os_info": None}

    def run_command(self, cmd):
        """Run a shell command securely."""
        try:
            result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as e:
            return f"Error: {str(e)}"

    def enum_os(self):
        """Retrieve OS information via SMB."""
        auth = f"-U \"{shlex.quote(self.username)}%{shlex.quote(self.password)}\"" if self.username and self.password else "-N"
        cmd = f"smbclient //{self.target}/IPC$ {auth} -t 1 -c exit"
        output = self.run_command(cmd)
        for line in output.splitlines():
            if "Domain=" in line:
                self.results["os_info"] = line
                print(f"[+] {self.target}: {line}")
            elif "NT_STATUS_LOGON_FAILURE" in line:
                print(f"[-] {self.target}: Authentication Failed")
                return False
        return True

    def get_domain_sid(self):
        """Retrieve the domain SID using rpcclient."""
        print(f"[*] Enumerating Domain Information for: {self.target}")
        auth = f"-U \"{shlex.quote(self.username)}%{shlex.quote(self.password)}\"" if self.username and self.password else "-N"
        cmd = f"rpcclient -c lsaquery {auth} {self.target}"
        output = self.run_command(cmd)
        for line in output.splitlines():
            if "Domain Name:" in line:
                print(f"[+] {line}")
            elif "Domain Sid:" in line:
                self.domain_sid = line.split(":")[1].strip()
                print(f"[+] Domain SID: {self.domain_sid}")
        if not self.domain_sid:
            print("[-] Could not attain Domain SID")

    def enum_shares(self):
        """List available SMB shares."""
        print(f"[*] Enumerating Shares for: {self.target}")
        auth = f"-U \"{shlex.quote(self.username)}%{shlex.quote(self.password)}\"" if self.username and self.password else "-N"
        cmd = f"smbclient -L {self.target} {auth} -t 2"
        output = self.run_command(cmd)
        acquired_shares = []
        for line in output.splitlines():
            if 'Disk' in line or 'IPC' in line or 'Printer' in line:
                share = line.split()[0].strip()
                print(f"    \\\\{self.target}\\{share}")
                acquired_shares.append(share)
        self.results["shares"] = acquired_shares

    def enum_users(self):
        """Enumerate users using querydispinfo and RID cycling."""
        print(f"[*] Enumerating Users for: {self.target}")
        auth = f"-U \"{shlex.quote(self.username)}%{shlex.quote(self.password)}\"" if self.username and self.password else "-N"
        cmd = f"rpcclient -c querydispinfo {auth} {self.target}"
        output = self.run_command(cmd)
        for line in output.splitlines():
            if "Name:" in line:
                user = line.split("Name:")[1].strip()
                print(f"    {user}")
                self.results["users"].append(user)

    def export_results(self, filename="results.json"):
        """Save enumeration results to a JSON file."""
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"[+] Results exported to {filename}")

def main():
    """Main function to parse arguments and execute SMB enumeration."""
    parser = argparse.ArgumentParser(description="SMBEnumerator: Comprehensive SMB enumeration tool")
    parser.add_argument('-u', '--username', type=str, help="Username")
    parser.add_argument('-p', '--password', type=str, help="Password")
    parser.add_argument('-t', '--target', type=str, required=True, help="Target IP or hostname")
    parser.add_argument('-o', '--output', type=str, default="results.json", help="Output JSON file")
    
    args = parser.parse_args()
    
    enumerator = SMBEnumerator(args.target, args.username, args.password)
    
    print("[*] Starting SMB Enumeration...")
    
    if enumerator.enum_os():
        enumerator.enum_shares()
        enumerator.get_domain_sid()
        enumerator.enum_users()
    
    enumerator.export_results(args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Key Event Detected... Exiting.\n")
        sys.exit(0)
