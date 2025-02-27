# SMBEnumerator
SMBEnumerator is a powerful SMB (Server Message Block) enumeration tool designed to gather detailed information about Windows systems, including users, shared resources, domain groups, and operating system details. It leverages tools like smbclient and rpcclient to perform null-session enumeration, RID cycling, and more. Whether you're conducting security assessments or network audits, SMBEnumerator provides a streamlined way to extract critical information from SMB servers.

Key Features:

Enumerate domain users and shared resources.

Perform RID cycling to discover hidden users and groups.

Gather operating system and domain information.

Export results in JSON format for further analysis.

Supports both authenticated and null-session enumeration.

## Features

- Enumerate domain users.
- Enumerate shared resources.
- Enumerate domain groups and their members.
- Enumerate operating system information.
- Perform RID cycling to discover users and groups.

## Requirements

- Python 3.x
- `smbclient` and `rpcclient` installed on the system.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/SMBEnumerator.git
   cd SMBEnumerator
     ```
2.Install the dependencies:

  ```bash
pip install -r requirements.txt
  ```
Ensure smbclient and rpcclient are installed on your system. On Debian/Ubuntu, you can install them with:

  ```bash
sudo apt-get install smbclient
  ```
## Usage

To enumerate users and shares on an SMB server:

  ```bash

python3 smbenumerator.py -u "DOMAIN\\User" -p "Password" -users -shares 192.168.1.1
  ```

Available Options
-u, -U: Specify the username.

-p, -P: Specify the password.

-shares: Enumerate shared resources.

-users: Enumerate users.

-q, -quick: Perform a quick user enumeration.

-r, -rid: Perform only RID cycling.

-range: Specify a custom RID cycling range (default: 500-550).

-T: Specify the maximum number of threads for RID cycling (default: 15).

## Example Output
  ```
[*] Enumerating Shares for: 192.168.1.1
        Shares                      Comments
   -------------------------------------------
    \\192.168.1.1\IPC$             Remote IPC
    \\192.168.1.1\Shared           General Share

[*] Enumerating querydispinfo for: 192.168.1.1
    Administrator
    Guest
    JohnDoe

[*] 3 unique user(s) identified
[+] Writing users to file: ./nullinux_users.txt
  ```
## License
This project is licensed under the MIT License.

Developed by [Alexander B]

## 🤝 Contributing
This project thrives on community contributions. If you'd like to suggest improvements, report issues, or add new features, feel free to open a pull request.
If you’d like to support future development, you can do so here:

☕ [buymeacoffee.com/alexboteroh]
