import subprocess
import argparse
import os
import json

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
NC = "\033[0m"
BLACK = "\033[0;30m"
CYAN = "\033[0;36m"
WHITE = "\033[0;37m"
RESET = "\033[0m"
RED_BACK="\033[1;41m"

def banner():
     ascii_art = f"""
     {BLUE}    .--.{RESET}
     {BLUE}   |o_o |{RESET}   
     {BLUE}   |:_/ |{RESET}     {YELLOW}Linux Enumeration Script{RESET}
     {BLUE}  //   \\ \\{RESET}    {GREEN}[Scan | Analyze | Report]{RESET}
     {BLUE} (|     | ){RESET}
     {BLUE}/'\\_   _/`\\{RESET}     
     {BLUE}\\___)=(___/{RESET}     
     {RED}■{RESET} Must Check   ■{RED_BACK}CVE{NC}
     {GREEN}■{RESET} Safe         {BLUE}■{RESET} Info
     """
     print(ascii_art)

def print_mg(message, header=False):
    if header:
        print("\n" + "=" * 50)
        print(f"{message}".center(50))
        print("=" * 50)
    else:
        print(f"{YELLOW}[⌁]{NC} {message}")

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print_mg(f"Error running command {command}: {result.stderr.strip()}")
            return None
    except subprocess.TimeoutExpired:
        print_mg(f"Command {command} timed out.")
        return None
    except Exception as e:
        print_mg(f"Error executing command: {e}")
        return None

def save_report(report_data, filename='report.html'):
    with open(filename, 'w') as f:
        f.write(report_data)
    print_mg(f"Report saved as {filename}")

def user_info():
    print_mg("USER ENUMERATION INFORMATION", header=True)
    user_info={
        "Current User":{
            "cmd" :"whoami",
            "msg" :"Current User",
            "results" :[]
            },
        "User ID Info":{
            "cmd":"id 2>/dev/null",
            "msg":"Current User ID",
            "results":[]
            },
        "Admin (sudo) Users": {
            "cmd": "getent group sudo",
            "msg": "Admin (sudo) Users",
            "results": []
            },
        "User Privileges":{
            "cmd":"sudo -l 2>/dev/null",
            "msg":"Current User Sudo Privileges",
            "results":[]
            },
        "Logged In Users":{
            "cmd":"w 2>/dev/null",
            "msg":"Logged in User Activity",
            "results":[]
            },
        "Last Logged In Users":{
            "cmd":"lastlog 2>/dev/null",
            "msg":"Shows the last login for all users",
            "results":[]
            },
        "Home Directories":{
            "cmd":"ls -ld /home/* 2>/dev/null",
            "msg":"Lists home directories with their permissions.",
            "results":[]
            },
        "User Passwords":{
            "cmd":"cat /cat/shadow 2>/dev/null",
            "msg":"Checks for read permissions on the /etc/shadow file.",
            "results":[]
            },
        "Groups":{
            "cmd":"for i in $(cut -d':' -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null",
            "msg":"Displays group information on the system.",
            "results":[]
            },
        "Sudo Users":{
            "cmd":"awk -F: '($3 == '0') {print}' /etc/passwd 2>/dev/null",
            "msg":"Shows which users are part of the sudo group.",
            "results":[]
            },
        "Root Access Files":{
            "cmd":"find / -user root 2>/dev/null",
            "msg":"Searches for files owned by root.",
            "results":[]
            }, 
        "Current Shell":{
            "cmd":"echo $SHELL",
            "msg":"Displays the current user's shell.",
            "results":[]
            },
        "User Accounts":{
            "cmd":"cat /etc/passwd 2>/dev/null",
            "msg":"Lists all user accounts and their default shells.",
            "results":[]
            },
        "Sudoers":{
            "cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null",
            "msg":"Sudoers (privileged)",
            "results":[]
            },
        "Screen":{
            "cmd":"screen -ls 2>/dev/null",
            "msg":"List out any screens running for the current user",
            "results":[]
            },
    }    
    for key, value in user_info.items():
        result = run_command(value["cmd"])
        if result:
            print_mg(f"{BLUE}{value['msg']}{NC}:\n{result}\n")
            value["results"].append(result)
        else:
            print_mg(f"\033[0;94m{value['msg']}\033[0m: No result")

def history_info():
    print_mg("COMMAND HISTORY INFORMATION", header=True)
    history_info={
        "Root":{
            "cmd": "ls -la /root/.*_history 2>/dev/null", 
            "msg": " See if you have access too Root user history (depends on privs)", 
            "results": []
            },
        "Bash":{
            "cmd":"cat ~/.bash_history 2>/dev/null",
            "msg":"Get the contents of bash history file for current user",
            "results":[]
            },
        "Nano":{
            "cmd":"cat ~/.nano_history 2>/dev/null",
            "msg":"Try to get the contents of nano history file for current user",
            "results":[]
            },
        "Ftp":{
            "cmd":"cat ~/.atftp_history 2>/dev/null",
            "msg":"Try to get the contents of atftp history file for current user",
            "results":[]
            },
        "Mysql":{
            "cmd":"cat ~/.mysql_history 2>/dev/null",
            "msg":"Try to get the contents of mysql history file for current user",
            "results":[]
            },
        "Php":{
            "cmd":"cat ~/.php_history 2>/dev/null",
            "msg":"Try to get the contents of php history file for current user",
            "results":[]
            },
        "Python":{
            "cmd":"cat ~/.python_history 2>/dev/null",
            "msg":"Try to get the contents of python history file for current user",
            "results":[]
            },
        "Rediscli":{
            "cmd":"cat ~/.rediscli_history 2>/dev/null",
            "msg":"Try to get the contents of redis cli history file for current user",
            "results":[]
            },
        "Tdsql":{
            "cmd":"cat ~/.tdsql_history 2>/dev/null",
            "msg":" Try to get the contents of tdsql history file for current user", 
            "results": []
            },
    }
    for key, value in history_info.items():
        result = run_command(value["cmd"])
        if result:
            print_mg(f"{BLUE}{value['msg']}{NC}:\n{result}\n")
            value["results"].append(result)
        else:
            print_mg(f"\033[0;94m{value['msg']}\033[0m: No result")

def network_info():
    print_mg("NETWORK INFORMATION", header=True)
    network_info={
        "Network Interface & IPs":{
            "cmd":"ip a 2>/dev/null",
            "msg":"Displays network interfaces and IP addresses",
            "results":[] 
            },
        "Routing Table":{
            "cmd":"netstat -rn 2>/dev/null",
            "msg":"Displays the current routing table",
            "results":[]
            },
        "Open Network Ports":{
            "cmd":"ss -tuln 2>/dev/null",
            "msg":"Shows active listening ports (TCP/UDP)",
            "results":[]
            },
        "Firewall Rules": {
            "cmd": "iptables -L 2>/dev/null || ufw status 2>/dev/null || firewall-cmd --list-all 2>/dev/null",
            "msg": "Lists all firewall rules (iptables, UFW, firewalld)",
            "results": []
            },
        "Active Network Connection":{
            "cmd":"netstat -atun 2>/dev/null",
            "msg":"Displays all established network connections",
            "results":[]
            },
        "DNS setting":{
            "cmd":"cat /etc/resolv.conf 2>/dev/null",
            "msg":"Checks DNS server configurations",
            "results":[]
            },
        "ARP Cache":{
            "cmd":"arp -a 2>/dev/null",
            "msg":"Displays ARP cache",
            "results":[]
            },
        "DHCP Leases": {
            "cmd": "cat /var/lib/dhcp/dhclient.leases 2>/dev/null",
            "msg": "Checks for active DHCP leases",
            "results": []
            },
        "Network Service":{
            "cmd":"netstat -plnt 2>/dev/null",
            "msg":"Lists network services and associated processes",
            "results":[]
            },
        "Proxy Setting":{
            "cmd":"env | grep -i proxy 2>/dev/null",
            "msg":"Checks if proxy settings are configured",
            "results":[]
            },
        "Current Network Config":{
            "cmd":"nmcli device show 2>/dev/null",
            "msg":"Displays network configuration for devices",
            "results":[]
            },
        "Host File":{
            "cmd":"cat /etc/hosts 2>/dev/null",
            "msg":"Checks local hostname resolution settings",
            "results":[]
            },
        "Network Share": {
            "cmd": "df -h 2>/dev/null | grep -iE '(nfs|cifs|smb)' || smbclient -L localhost 2>/dev/null || showmount -e 2>/dev/null",
            "msg": "Enumerates mounted network shares (NFS, CIFS, SMB)",
            "results": []
            },
        "Network Interface with Sensitive Permissions":{
            "cmd":"find / -perm -u=s -type f 2>/dev/null | xargs ls -la 2>/dev/null",
            "msg":"Looks for network-related files with SUID bit set",
            "results":[]
            },
        "Listening Sockets and Associated Processes": {
            "cmd": "lsof -i -n -P ", 
            "msg": "Lists all open files and associated network services",
            "results": []
            },
        "SNMP Configuration": {
            "cmd": "cat /etc/snmp/snmpd.conf", 
            "msg": "Checks for Simple Network Management Protocol (SNMP) configuration files",
            "results": []
        },
        "Check for VPN Configurations": {
            "cmd": "cat /etc/openvpn/*", 
            "msg": "Examines VPN configuration files if OpenVPN is installed.",
            "results": []
        },
        "Can I sniff with tcpdump?": {
            "cmd": f'''
            timeout 1 tcpdump >/dev/null 2>&1
            if [ $? -eq 124 ]; then
                echo "{RED}You can sniff with tcpdump!{NC}"
            else
                echo "{GREEN}You cannot sniff with tcpdump!{NC}"
            fi
            echo ""
             ''',
            "msg": "Check if tcpdump can be used for sniffing traffic.",
            "results": []
        },
    }
    for key, value in network_info.items():
        result = run_command(value["cmd"])
        if result:
            print_mg(f"{BLUE}{value['msg']}{NC}:\n{result}\n")
            value["results"].append(result)
        else:
            print_mg(f"\033[0;94m{value['msg']}\033[0m: No result")

def system_info():
    print_mg("SYSTEM INFORMATION", header=True)
    system_info = {
        # Basic Information sudoVersion
        "Kernel Version":{
            "cmd":"cat /proc/version",
            "msg": "Kernel Version",
            "results": []
            },
        "OS and Version":{
            "cmd":"cat /etc/os-release",
            "msg": "Operating System Information",
            "results": []
            },
        "System Architecture":{
            "cmd":"uname -m",
            "msg": "System Architecture",
            "results": []
            },
        "Hostname":{
            "cmd":"hostname",
            "msg": "System Hostname",
            "results": []
            },
        "System Uptime":{
            "cmd":"uptime",
            "msg": "System Uptime",
            "results": []
            },
        "Last Reboot":{
            "cmd":"who -b",
            "msg": "Last Reboot",
            "results": []
            },
        "Kernel Messages":{
            "cmd":"dmesg | tail -n 50",
            "msg": "Recent Kernel Messages",
            "results": []
            },
        "System Services":{
            "cmd":"systemctl list-units --type=service",
            "msg": "Running System Services",
            "results": []
            },
        "Installed Packages":{
            "cmd":"dpkg -l | head",
            "msg": "Installed Packages",
            "results": []
            },
        "Sudo Version":{
            "cmd":"sudo -V",
            "msg":"Sudo Version",
            "results":[]
            },
        # System Resource and Process Info
        "Memory Info":{
            "cmd":"cat /proc/meminfo",
            "msg": "Memory Information",
            "results": []
            },
        "CPU Info":{
            "cmd":"cat /proc/cpuinfo",
            "msg": "CPU Information",
            "results": []
            },
        "Running Processes":{
            "cmd":"ps aux",
            "msg": "Processes Running",
            "results": []
            },
        "Running Services":{
            "cmd":"systemctl list-units --type=service --state=running",
            "msg": "Running Services",
            "results": []
            },
        # Advanced Enumeration
        "Environment Variables":{
            "cmd":"env",
            "msg": "Environment Variables",
            "results": []
            },
        "Available Shells":{
            "cmd":"cat /etc/shells",
            "msg": "Available Shells",
            "results": []
            },     
        # Kernel Modules and Devices
        "Loaded Kernel Modules":{
            "cmd":"lsmod",
            "msg": "Loaded Kernel Modules",
            "results": []
            },
        "Running Kernel Parameters":{
            "cmd":"sysctl -a 2>/dev/null | head",
            "msg": "Current Kernel Parameters",
            "results": []
            },
        "Block Devices Info":{
            "cmd":"lsblk",
            "msg": "Block Devices Information",
            "results": []
            },
        # Audit Logs and System Logs
        "Audit Logs":{
            "cmd":"cat /var/log/audit/audit.log",
            "msg": "Audit Logs",
            "results": []
            },
        "System Logs":{
            "cmd":"dmesg | tail -n 25",
            "msg": "Recent System Logs",
            "results": []
            }
    }
    for key, value in system_info.items():
        result = run_command(value["cmd"])
        if result:
            print_mg(f"{BLUE}{value['msg']}{NC}:\n{result}\n")
            value["results"].append(result)
        else:
            print_mg(f"\033[0;94m{value['msg']}\033[0m: No result")

def protection_info():
    print_mg("Protections and Measure", header=True)
    protection_info={
        "AppArmor enabled":{
            "cmd":"command -v aa-status || command -v apparmor_status || ls -d /etc/apparmor*",
            "msg": "AppArmor enabled?",
            "results": []
            },
        "AppArmor Profile":{
            "cmd":f"cat /proc/self/attr/current || echo '{RED}unconfined{NC}'",
            "msg": "AppArmor profile?",
            "results": []
            },
        "LinuxONE":{
            "cmd":"( (uname -a | grep's390x' >/dev/null 2>&1) && echo 'Yes' || echo 's390x Not Found')",
            "msg": "LinuxONE?",
            "results": []
            },
        "Grsecurity check":{
            "cmd":"uname -r | grep '\-grsec' >/dev/null 2>&1 || grep 'grsecurity' /etc/sysctl.conf >/dev/null 2>&1 && echo 'Yes' || echo 'grsecurity Not Found'",
            "msg": "Grsecurity?",
            "results": []
            },
        "PaX check":{
            "cmd":"command -v paxctl-ng paxctl >/dev/null 2>&1 && echo 'Yes' || echo 'PaX Not Found'",
            "msg": "PaX bins?",
            "results": []
            },
        "Execshield check":{
            "cmd":f"(grep 'exec-shield' /etc/sysctl.conf 2>/dev/null || echo 'Execshield Not Found')",
            "msg": "Execshield enabled?",
            "results": []
            },
        "SELinux":{
            "cmd":f"(sestatus 2>/dev/null || echo 'sestatus Not Found') | sed 's/disabled/{RED}disabled{NC}/'",
            "msg":"SELinux enabled?",
            "results":[]
        },
        "Seccomp check":{
            "cmd": """
                seccomp_status=$(grep '^Seccomp' /proc/self/status 2>/dev/null)
                if [ -z "$seccomp_status" ]; then
                    echo -e "Not found{NC}"
                elif [ "$seccomp_status" = "0" ]; then
                    echo "\033[0;31mDisabled\033[0m ($seccomp_status)"
                else
                    echo "\033[0;32mEnabled\033[0m ($seccomp_status)"
                fi
                """,
            "msg": "Seccomp enabled?",
            "results": []
            },
       "User Namespace": {
            "cmd": f'''
                if grep Seccomp: /proc/self/status 2>/dev/null | grep '0' >/dev/null; then 
                    echo "{GREEN}enabled{NC}"; 
                else 
                    echo "{RED}disabled{NC}"; 
                fi
            ''',
            "msg": "User namespace?",
            "results": []
            },
        "Cgroup2":{
            "cmd":f"([ '$(grep cgroup2 /proc/filesystems 2>/dev/null)' ] && echo '{GREEN}enabled{NC}' || echo '{RED}disabled{NC}')",
            "msg":"Cgroup2 enabled?",
            "results":[]
        },
        "ASLR":{
            "cmd":f'''
                    ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
                    if [ -z "$ASLR" ]; then
                        echo "/proc/sys/kernel/randomize_va_space";
                    else
                        if [ "$ASLR" -eq "0" ]; then 
                            echo {RED}"No"{NC}; 
                        else 
                            echo "{GREEN}Yes{NC}"; 
                        fi
                        echo ""
                    fi
                    ''',
            "msg":"Is ASLR enabled?",
            "results":[]
        },
        "Printer":{
            "cmd":"(lpstat -a || system_profiler SPPrintersDataType || echo 'no') 2>/dev/null",
            "msg":"Printer?",
            "results":[]
        },
        "virtual machine?": {
            "cmd": f'''
                    hypervisorflag=$(grep flags /proc/cpuinfo 2>/dev/null | grep hypervisor)
                    if [ "$(command -v systemd-detect-virt 2>/dev/null || echo -n '')" ]; then
                        detectedvirt=$(systemd-detect-virt)
                        if [ "$hypervisorflag" ]; then 
                            printf "{RED}Yes ($detectedvirt){NC}"; 
                        else 
                            printf "{GREEN}No{NC}"; 
                        fi
                    else
                        if [ "$hypervisorflag" ]; then 
                            echo "{RED}Yes{NC}"; 
                        else 
                            echo "{GREEN}No{NC}"; 
                        fi
                    fi
                ''',
            "msg": "Is this a virtual machine?",
            "results": []
        },
    }
    for key, value in protection_info.items():
        result = run_command(value["cmd"])
        if result:
            print_mg(f"{BLUE}{value['msg']}{NC}:{result}")
            value["results"].append(result)
        else:
            print_mg(f"\033[0;94m{value['msg']}\033[0m: No result")

def container_info():
    print_mg("Container and Docker Information", header=True)
    container_checks = {
        "Container Management Tools Installed": {
            "cmd": f"""con=$(which docker lxc rkt podman kubectl runc) 
            if [ -n "$con" ]; then
                echo '{RED}Container tools found{NC}'
                echo $con
            else
                echo 'No container tools found'
            fi""",
            "msg": "Are container management tools (Docker, LXC, Rkt, Podman , kubectl , runc) installed?",
            "results": []
        },
        "List Mounted Tokens": {
            "cmd": "grep -E '(TOKEN|PASS|SECRET)' /proc/mounts || echo 'No sensitive tokens found'",
            "msg": "Searching for sensitive tokens in mounted filesystems",
            "results": []
        },
        "List All Docker Containers (Running and Stopped)": {
            "cmd": f"""
                docker=$(docker ps -a --no-trunc 2>/dev/null )
                lxc=$(lxc-ls --fancy 2>/dev/null )
                podman=$(podman ps -a --no-trunc 2>/dev/null )
                rkt=$(rkt list 2>/dev/null )l
               
                if [ -n "$docker" ]; then
                    echo "{RED}\nDocker containers:{NC}"
                    echo "$docker"
                fi
                if [ -n "$lxc" ]; then
                    echo "{RED}LXC containers:{NC}"
                    echo "$lxc"
                fi
                if [ -n "$podman" ]; then
                    echo "{RED}Podman containers:{NC}"
                    echo "$podman"
                fi
                if [ -n "$rkt" ]; then      
                    echo "{RED}Rkt containers:{NC}"
                    echo "$rkt"
                fi  
            """,
            "msg": "Listing details of all containers (running and stopped) for Docker, LXC, Rkt, and Podman",
            "results": []
        },
        "Inspect Running Docker Containers for Detailed Information": {
             "cmd": """
                # Docker inspection
                if command -v docker >/dev/null 2>&1; then
                    if [ "$(docker ps -q)" ]; then
                    echo "Docker containers:"
                        docker ps -q | while read container; do
                            docker inspect "$container"
                        done
                    else
                        echo "No running Docker containers found."
                    fi
                else
                    echo "Docker is not installed."
                fi

                # LXC inspection
                if command -v lxc-info >/dev/null 2>&1; then
                    if [ "$(lxc-ls)" ]; then
                        lxc-info --name $(lxc-ls) 2>/dev/null || echo 'Cannot inspect LXC containers'
                    else
                        echo "No LXC containers found."
                    fi
                else
                    echo "LXC is not installed."
                fi

                # Podman inspection
                if command -v podman >/dev/null 2>&1; then
                    if [ "$(podman ps -q)" ]; then
                        podman ps -q | while read container; do
                            podman inspect "$container"
                        done
                    else
                        echo "No running Podman containers found."
                    fi
                else
                    echo "Podman is not installed."
                fi
            """,
            "msg": "Gathering detailed information about running Docker, LXC, Podman, and Rkt containers",
            "results": []
        },
        f"Check for Container Breakout Potential {RED}(CVE-2019-5736){NC}": {
            "cmd": "docker exec -it $(docker ps -q | head -n1) sh 2>/dev/null && echo 'Breakout possible' || echo 'No breakout possible'",
            "msg": "Checking if container breakout is possible (CVE-2019-5736)",
            "results": []
        },
        "Determine if Running Inside a Container (Am I contained?)": {
            "cmd": "grep -E 'docker|lxc|kubepods' /proc/1/cgroup && echo 'Running inside a container' || echo 'Not running in a container'",
            "msg": "Is the system running inside a container?",
            "results": []
        },
        "Gather Information About Container Namespaces": {
            "cmd": "lsns -t net,ipc,uts,pid,user,mnt || echo 'Cannot retrieve namespace information'",
            "msg": "Container namespace information",
            "results": []
        },
        "Check Control Groups (cgroups) Configuration": {
            "cmd": "cat /proc/self/cgroup || echo 'No cgroup information found'",
            "msg": "Control group (cgroup) information",
            "results": []
        },
        "Inspect Container Security Profiles (AppArmor/SELinux)": {
            "cmd": "docker inspect --format '{{.HostConfig.SecurityOpt}}' $(docker ps -q) || echo 'No security profiles detected'",
            "msg": "Are there security profiles like AppArmor or SELinux enabled?",
            "results": []
        },
        "Test Docker Escape Techniques (HackTricks)": {
            "cmd": "docker exec -it $(docker ps -q | head -n1) /bin/sh || echo 'No escape possible'",
            "msg": "Testing Docker escape techniques",
            "results": []
        },
        "Search for Docker-Related Directories": {
            "cmd": "find / -name '*docker*' -type d 2>/dev/null || echo 'No Docker directories found'",
            "msg": "Searching for sensitive Docker directories",
            "results": []
        },
        "Check if Any Containers are Running as Root": {
            "cmd": "docker ps --filter 'status=running' --filter 'user=root' || echo 'No containers running as root'",
            "msg": "Are containers running as root?",
            "results": []
        },
        "Check Docker Socket Permissions": {
            "cmd": "ls -l /var/run/docker.sock | grep docker || echo 'Docker socket not found or not accessible'",
            "msg": "Checking if Docker socket can be misused",
            "results": []
        },
        "Check Linux Capabilities Added to Containers": {
            "cmd": "docker inspect --format='{{.HostConfig.CapAdd}}' $(docker ps -q) || echo 'No capabilities added to containers'",
            "msg": "Checking Linux capabilities added to containers",
            "results": []
        },
        "Gather Container Runtime Information (Docker Version)": {
            "cmd": "docker version || echo 'Docker not found'",
            "msg": "Gathering container runtime information",
            "results": []
        },
        "Check if PID 1 is systemd or init (Indicates Container)": {
            "cmd": "ps -p 1 -o comm= || echo 'Cannot retrieve PID 1 information'",
            "msg": "Checking if PID 1 is systemd or init (indicates container)",
            "results": []
        },
        "Check Docker Environment Variables for Sensitive Data": {
            "cmd": "docker inspect --format='{{.Config.Env}}' $(docker ps -q) || echo 'No running containers or no env vars found'",
            "msg": "Checking if Docker environment variables contain sensitive data",
            "results": []
        },
        "Check for Open Ports in Running Containers": {
            "cmd": "docker ps --format '{{.Ports}}' || echo 'No running containers with exposed ports'",
            "msg": "Checking for open ports in running containers",
            "results": []
        },
        "Audit Docker Logs for Security Information": {
            "cmd": """
            if command -v journalctl >/dev/null 2>&1; then
                journalctl -u docker -n 50 || echo 'No Docker logs found'
            else
                echo 'journalctl is not available on this system.'
            fi
            """,
            "msg": "Auditing Docker logs for security information",
            "results": []
        },
        "Check for Container File Mounts (Sensitive Directories)": {
            "cmd": "docker inspect --format '{{ .Mounts }}' $(docker ps -q) || echo 'No mounts found'",
            "msg": "Checking for sensitive file mounts in containers",
            "results": []
        },
    }

    for key, value in container_checks.items():
        result = run_command(value["cmd"])
        if result:
            print_mg(f"\033[0;94m{value['msg']}\033[0m: {result}")
            value["results"].append(result)
        else:
            print_mg(f"\033[0;94m{value['msg']}\033[0m: No result")

def main():
    parser = argparse.ArgumentParser(banner())
    parser.add_argument("-u","--user", help="Check user information", action="store_true")
    parser.add_argument("-his","--history", help="Check history information", action="store_true")
    parser.add_argument("-n","--network", help="Check network information", action="store_true")
    parser.add_argument("-s","--system", help="Check system information", action="store_true")
    parser.add_argument("-p","--protection", help="Check protection information", action="store_true")
    parser.add_argument("-c","--container", help="Check container information", action="store_true")
    # parser.add_argument("-f","--filesystem", help="Check filesystem information", action="store_true")
    # parser.add_argument("-cj","--cronjobs", help="Check cronjobs information", action="store_true")
    parser.add_argument("--all", help="Check all information", action="store_true")
    args = parser.parse_args()

    if args.all:
        user_info()
        history_info()
        network_info()
        system_info()
        protection_info()
        container_info()
        filesystem_info()
        cronjobs_info()
    else:
        if args.user:
            user_info()
        if args.history:
            history_info()
        if args.network:
            network_info()
        if args.system:
            system_info()
        if args.protection:
            protection_info()
        if args.container:
            container_info()
        # if args.filesystem:
        #     filesystem_info()
        # if args.cronjobs:
        #     cronjobs_info()

if __name__ == "__main__":
    main()




