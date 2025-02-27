#!/usr/bin/env python3
from __future__ import print_function
import sys
import argparse
import datetime
import json
from time import sleep
from threading import Thread, activeCount
from ipparser import ipparser

if sys.version_info[0] < 3:
    from commands import getoutput
else:
    from subprocess import getoutput

class SMBEnumerator:
    known_users = ['Administrator', 'Guest', 'krbtgt', 'root', 'bin']
    domain_sid = ""
    acquired_users = []
    results = {}

    def __init__(self, username=None, password=None, verbose=False):
        self.username = username
        self.password = password
        self.verbose = verbose
        self.results = {"users": [], "shares": [], "groups": [], "os_info": None}

    def run_command(self, cmd):
        try:
            return getoutput(cmd)
        except Exception as e:
            print_failure(f"Command failed: {e}")
            return ""

    def enum_os(self, target):
        auth = f"-U {self.username}%{self.password}" if self.username and self.password else ""
        cmd = f"smbclient //{target}/IPC$ {auth} -t 1 -c exit"
        output = self.run_command(cmd)
        for line in output.splitlines():
            if "Domain=" in line:
                self.results["os_info"] = line
                print_success(f"{target}: {line}")
            elif "NT_STATUS_LOGON_FAILURE" in line:
                print_failure(f"{target}: Authentication Failed")
                return False
        return True

    def get_dom_sid(self, target):
        print("\n\033[1;34m[*]\033[1;m Enumerating Domain Information for: {}".format(target))
        auth = f"-U {self.username}%{self.password}" if self.username and self.password else ""
        cmd = f"rpcclient -c lsaquery {auth} {target}"
        output = self.run_command(cmd)
        for line in output.splitlines():
            if "Domain Name:" in line:
                print_success(line)
            elif "Domain Sid:" in line:
                self.domain_sid = line.split(":")[1].strip()
                print_success(f"Domain SID: {self.domain_sid}")
        if not self.domain_sid:
            print_failure("Could not attain Domain SID")

    def enum_shares(self, target):
        count = 0
        acquired_shares = []
        smbclient_types = ['Disk', 'IPC', 'Printer']
        print("\n\033[1;34m[*]\033[1;m Enumerating Shares for: {}".format(target))
        auth = f"-U {self.username}%{self.password}" if self.username and self.password else ""
        cmd = f"smbclient -L {target} {auth} -t 2"
        output = self.run_command(cmd)
        for line in output.splitlines():
            if count == 0:
                print("        {:26} {}".format("Shares", "Comments"))
                print("   " + "-" * 43)
            count += 1
            for t in smbclient_types:
                if t in line:
                    try:
                        if 'IPC$' in line:
                            print(f"    \\\\{target}\\IPC$")
                            acquired_shares.append("IPC$")
                        else:
                            share = line.split(t)[0].strip()
                            comment = line.split(t)[1].strip()
                            print(f"    \\\\{target}\\{share:15} {comment}")
                            acquired_shares.append(share)
                    except KeyboardInterrupt:
                        print("\n[!] Key Event Detected...\n\n")
                        sys.exit(0)
                    except:
                        pass
        if acquired_shares:
            self.results["shares"] = acquired_shares
            for s in acquired_shares:
                self.enum_dir(target, s)
        else:
            print("   ")
            print_failure("No Shares Detected")

    def enum_dir(self, target, share):
        header_count = 0
        auth = f"-U {self.username}%{self.password}" if self.username and self.password else ""
        cmd = f"smbclient //{target}/\'{share}\' -t 3 {auth} -c dir"
        output = self.run_command(cmd)
        for line in output.splitlines():
            if "NT_STATUS" in line or "_ACCESS_DENIED" in line:
                if self.verbose:
                    if header_count == 0:
                        header_count += 1
                        self.share_header(target, share)
                    print("   ", end='')
                    print_failure(line)
            elif "Domain=" in line or "blocks available" in line or "WARNING" in line or "failed:" in line or not line:
                pass
            else:
                if header_count == 0:
                    header_count += 1
                    self.share_header(target, share)
                print("     " + line)

    def enum_querydispinfo(self, target):
        print("\n\033[1;34m[*]\033[1;m Enumerating querydispinfo for: {}".format(target))
        auth = f"-U {self.username}%{self.password}" if self.username and self.password else ""
        cmd = f"rpcclient -c querydispinfo {auth} {target}"
        output = self.run_command(cmd)
        for line in output.splitlines():
            try:
                user_account = line.split("Name:")[0].split("Account:")[1].strip()
                print("    " + user_account)
                if user_account not in self.acquired_users:
                    self.acquired_users.append(user_account)
                    self.results["users"].append(user_account)
            except KeyboardInterrupt:
                print("\n[!] Key Event Detected...\n\n")
                sys.exit(0)
            except:
                pass

    def rid_cycling(self, target, ridrange, max_threads):
        print("\n\033[1;34m[*]\033[1;m Performing RID Cycling for: {}".format(target))
        if not self.domain_sid:
            print_failure("RID Failed: Could not attain Domain SID")
            return False
        try:
            r = ridrange.split("-")
            rid_range = list(range(int(r[0]), int(r[1]) + 1))
        except:
            print_failure("Error parsing custom RID range, reverting to default")
            rid_range = list(range(500, 551))
        for rid in rid_range:
            try:
                Thread(target=self.rid_thread, args=(rid, target), daemon=True).start()
            except:
                pass
            while activeCount() > max_threads:
                sleep(0.001)
        while activeCount() > 1:
            sleep(0.001)

    def rid_thread(self, rid, target):
        auth = f"-U {self.username}%{self.password}" if self.username and self.password else ""
        cmd = f"rpcclient -c \"lookupsids {self.domain_sid}-{rid}\" {auth} {target}"
        output = self.run_command(cmd)
        for line in output.splitlines():
            if "S-1-5-21" in line:
                user_account = line.split("\\")[1].split("(")[0].strip()
                count = int(line.split("(")[1].split(")")[0].strip())
                if count == 1:
                    if self.verbose:
                        print("    " + line)
                    else:
                        print("    " + user_account)
                    if user_account not in self.acquired_users:
                        self.acquired_users.append(user_account)
                        self.results["users"].append(user_account)
                elif count > 1 and "*unknown*\*unknown*" not in line:
                    if self.verbose:
                        print("    {:35} (Network/LocalGroup)".format(line))
                    else:
                        print("    {:35} (Network/LocalGroup)".format(user_account))

    def export_results(self, filename="results.json"):
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print_success(f"Results exported to {filename}")

def print_success(msg):
    print('\033[1;32m[+]\033[0m {}'.format(msg))

def print_status(msg):
    print('\033[1;34m[*]\033[0m {}'.format(msg))

def print_failure(msg):
    print('\033[1;31m[-]\033[0m {}'.format(msg))

def time_stamp():
    return datetime.datetime.now().strftime('%m-%d-%Y %H:%M')

def main(args):
    print("\n    Starting SMBEnumerator v{} | {}\n\n".format(version, time_stamp()))
    scan = SMBEnumerator(args.username, args.password, args.verbose)
    for t in args.target:
        try:
            if args.rid_only:
                scan.get_dom_sid(t)
                scan.rid_cycling(t, args.rid_range, args.max_threads)
            else:
                scan.enum_os(t)
                if args.users:
                    scan.enum_shares(t)
                if args.shares:
                    if not scan.domain_sid:
                        scan.get_dom_sid(t)
                    scan.enum_querydispinfo(t)
                    if not args.quick:
                        scan.rid_cycling(t, args.rid_range, args.max_threads)
        except Exception as e:
            print("\n[*] Main Error: {}\n\n".format(e))

    if args.users:
        print("\n\033[1;34m[*]\033[1;m {} unique user(s) identified".format(len(scan.acquired_users)))
        if scan.acquired_users:
            print("\033[1;32m[+]\033[1;m Writing users to file: ./nullinux_users.txt\n")
            scan.export_results()

if __name__ == '__main__':
    try:
        version = '1.0.0'
        args = argparse.ArgumentParser(description=("""
               SMBEnumerator | v{0}
    -----------------------------------
SMB enumeration tool to gather OS, user, share, and domain information.

usage:
    smbenumerator -users -quick DC1.demo.local,10.0.1.1
    smbenumerator -rid -range 500-600 10.0.0.1
    smbenumerator -shares -U 'Domain\\User' -P 'Password1' 10.0.0.1""").format(version), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
        args.add_argument('-v', dest="verbose", action='store_true', help="Verbose output")
        auth = args.add_argument_group("Authentication")
        auth.add_argument('-u', '-U', dest='username', type=str, default=None, help='Username')
        auth.add_argument('-p', '-P', dest='password', type=str, default=None, help='Password')
        enum = args.add_argument_group("Enumeration")
        enum.add_argument('-shares', dest="shares", action='store_false', help="Enumerate shares only")
        enum.add_argument('-users', dest="users", action='store_false', help="Enumerate users only")
        enum.add_argument('-q', '-quick', dest="quick", action='store_true', help="Fast user enumeration")
        enum.add_argument('-r', '-rid', dest="rid_only", action='store_true', help="Perform RID cycling only")
        enum.add_argument('-range', dest='rid_range', type=str, default="500-550", help='Set Custom RID cycling range (Default: \'500-550\')')
        enum.add_argument('-T', dest='max_threads', type=int, default=15, help='Max threads for RID cycling (Default: 15)')
        args.add_argument(dest='target', nargs='+', help='Target server')
        args = args.parse_args()
        args.target = ipparser(args.target[0])
        main(args)
    except KeyboardInterrupt:
        print("\n[!] Key Event Detected...\n\n")
        sys.exit(0)