# Linux-Enumeration

This repository contains a Linux enumeration script to assist in identifying misconfigurations, privilege escalation paths, and security vulnerabilities on Linux systems. The tool scans various aspects of the system and categorizes findings based on severity, helping security professionals quickly assess potential issues.

## Usage
```bash

     .--.
    |o_o |
    |:_/ |     Linux Enumeration Script
   //   \ \    [Scan | Analyze | Report]
  (|     | )
 /'\_   _/`\
 \___)=(___/
 ■ Must Check   ■CVE
 ■ Safe         ■ Info

$ python3 lin.py [-h] [-u] [-his] [-n] [-s] [-p] [-c] [--all]

options:
  -h, --help        show this help message and exit
  -u, --user        Check user information
  -his, --history   Check history information
  -n, --network     Check network information
  -s, --system      Check system information
  -p, --protection  Check protection information
  -c, --container   Check container information
  --all             Check all information

```
## References
- [Steflan Security Linux Privilege Escalation Guide](https://steflan-security.com/category/guides/privilegeescalation/linux/)
- [HackTricks Linux Hardening](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [linPEAS](https://github.com/peass-ng/PEASS-ng)
- [Linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker/tree/master)


## Note
This script is part of an ongoing project aimed at creating a comprehensive Linux privilege escalation tool.
