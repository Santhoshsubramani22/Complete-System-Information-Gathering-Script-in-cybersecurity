#!/usr/bin/env python3
"""
Complete System Information Gathering Script
Shows all details directly in output
For authorized security assessments only
"""

import os
import sys
import platform
import subprocess
import socket
import psutil
import datetime
import getpass
import json

# Suppress warnings for cleaner output
import warnings
warnings.filterwarnings("ignore")

def print_section(title):
    """Print a section header"""
    print("\n" + "="*80)
    print(f"{title.upper()}")
    print("="*80)

def print_subsection(title):
    """Print a subsection header"""
    print(f"\n--- {title} ---")

def safe_run_command(command, timeout=5):
    """Safely run a system command and return its output"""
    try:
        result = subprocess.run(
            command.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip() if result.stdout else "N/A"
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
        return "N/A"

def get_hardware_info():
    """Collect detailed hardware information"""
    print_section("HARDWARE INFORMATION")
    
    # System information
    print_subsection("System Details")
    print(f"{'Manufacturer':<25}: {safe_run_command('dmidecode -s system-manufacturer')}")
    print(f"{'Model':<25}: {safe_run_command('dmidecode -s system-product-name')}")
    print(f"{'Serial Number':<25}: {safe_run_command('dmidecode -s system-serial-number')}")
    
    # CPU Information
    print_subsection("CPU Details")
    print(f"{'Physical cores':<25}: {psutil.cpu_count(logical=False)}")
    print(f"{'Logical cores':<25}: {psutil.cpu_count(logical=True)}")
    
    if psutil.cpu_freq():
        print(f"{'Max frequency':<25}: {psutil.cpu_freq().max:.2f} MHz")
        print(f"{'Current frequency':<25}: {psutil.cpu_freq().current:.2f} MHz")
    
    print(f"{'Current usage':<25}: {psutil.cpu_percent(interval=1)}%")
    
    # Per-CPU usage
    print("CPU Usage per Core:")
    for i, percent in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
        print(f"  Core {i}: {percent}%")
    
    # Memory Information
    print_subsection("Memory Details")
    memory = psutil.virtual_memory()
    print(f"{'Total memory':<25}: {memory.total / (1024**3):.2f} GB")
    print(f"{'Available memory':<25}: {memory.available / (1024**3):.2f} GB")
    print(f"{'Used memory':<25}: {memory.used / (1024**3):.2f} GB")
    print(f"{'Memory percentage':<25}: {memory.percent}%")
    
    # Swap Information
    swap = psutil.swap_memory()
    print(f"{'Swap total':<25}: {swap.total / (1024**3):.2f} GB")
    print(f"{'Swap used':<25}: {swap.used / (1024**3):.2f} GB")
    print(f"{'Swap percentage':<25}: {swap.percent}%")
    
    # Disk Information
    print_subsection("Disk Details")
    partitions = psutil.disk_partitions()
    print(f"{'Device':<20} {'Mountpoint':<15} {'Filesystem':<10} {'Total':<10} {'Used':<10} {'Free':<10} {'Percentage'}")
    print("-" * 80)
    
    for partition in partitions:
        print(f"{partition.device:<20} {partition.mountpoint:<15} {partition.fstype:<10}", end="")
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
            print(f" {partition_usage.total / (1024**3):<9.2f}GB {partition_usage.used / (1024**3):<9.2f}GB {partition_usage.free / (1024**3):<9.2f}GB {partition_usage.percent:<9.2f}%")
        except PermissionError:
            print(" Permissions denied")

def get_software_info():
    """Collect software information"""
    print_section("SOFTWARE INFORMATION")
    
    # OS Information
    print_subsection("Operating System")
    print(f"{'Platform':<20}: {platform.platform()}")
    print(f"{'System':<20}: {platform.system()}")
    print(f"{'Release':<20}: {platform.release()}")
    print(f"{'Version':<20}: {platform.version()}")
    print(f"{'Machine':<20}: {platform.machine()}")
    print(f"{'Processor':<20}: {platform.processor()}")
    print(f"{'Architecture':<20}: {platform.architecture()[0]}")
    print(f"{'Hostname':<20}: {socket.gethostname()}")
    print(f"{'FQDN':<20}: {socket.getfqdn()}")
    print(f"{'Boot time':<20}: {datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Kernel Information (Unix/Linux)
    if sys.platform != "win32":
        print_subsection("Kernel Details")
        print(f"{'Kernel info':<20}: {safe_run_command('uname -a')}")
        print(f"{'Kernel version':<20}: {safe_run_command('uname -r')}")
    
    # Python Information
    print_subsection("Python Environment")
    print(f"{'Python version':<20}: {sys.version}")
    print(f"{'Python compiler':<20}: {platform.python_compiler()}")
    print(f"{'Python build':<20}: {platform.python_build()[0]}")
    print(f"{'Python implementation':<20}: {platform.python_implementation()}")

def get_network_info():
    """Collect network information"""
    print_section("NETWORK INFORMATION")
    
    # IP Addresses
    print_subsection("IP Configuration")
    hostname = socket.gethostname()
    print(f"{'Hostname':<20}: {hostname}")
    try:
        print(f"{'Private IP':<20}: {socket.gethostbyname(hostname)}")
    except:
        print(f"{'Private IP':<20}: Unable to resolve")
    
    # Network Interfaces
    print_subsection("Network Interfaces")
    if_addrs = psutil.net_if_addrs()
    for interface_name, interface_addresses in if_addrs.items():
        print(f"\nInterface: {interface_name}")
        for address in interface_addresses:
            if str(address.family) == 'AddressFamily.AF_INET':
                print(f"  IPv4 Address: {address.address}")
                print(f"  Netmask: {address.netmask}")
                print(f"  Broadcast IP: {address.broadcast}")
            elif str(address.family) == 'AddressFamily.AF_INET6':
                print(f"  IPv6 Address: {address.address}")
            elif 'AF_LINK' in str(address.family):
                print(f"  MAC Address: {address.address}")
    
    # Network Statistics
    print_subsection("Network Statistics")
    net_io = psutil.net_io_counters()
    print(f"{'Bytes sent':<20}: {net_io.bytes_sent:,} bytes")
    print(f"{'Bytes received':<20}: {net_io.bytes_recv:,} bytes")
    print(f"{'Packets sent':<20}: {net_io.packets_sent:,}")
    print(f"{'Packets received':<20}: {net_io.packets_recv:,}")
    print(f"{'Errors in':<20}: {net_io.errin}")
    print(f"{'Errors out':<20}: {net_io.errout}")
    print(f"{'Drop in':<20}: {net_io.dropin}")
    print(f"{'Drop out':<20}: {net_io.dropout}")
    
    # Active Connections
    print_subsection("Active Network Connections")
    connections = psutil.net_connections(kind='inet')
    print(f"{'Proto':<8} {'Local Address':<25} {'Remote Address':<25} {'Status':<15}")
    print("-" * 80)
    for conn in connections:
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        print(f"{str(conn.type):<8} {laddr:<25} {raddr:<25} {conn.status:<15}")

def get_application_info():
    """Collect application and process information"""
    print_section("APPLICATION AND PROCESS INFORMATION")
    
    # Running Processes
    print_subsection("Running Processes (Top 20 by CPU usage)")
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'create_time']):
        try:
            proc_info = proc.info
            if proc_info['create_time']:
                proc_info['uptime'] = str(datetime.datetime.now() - datetime.datetime.fromtimestamp(proc_info['create_time']))
            processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    # Sort by CPU usage
    processes.sort(key=lambda x: x['cpu_percent'] if x['cpu_percent'] is not None else 0, reverse=True)
    
    print(f"{'PID':<10} {'Name':<25} {'User':<15} {'CPU%':<8} {'Memory%':<10} {'Uptime':<20}")
    print("-" * 90)
    for i, proc in enumerate(processes[:20]):
        print(f"{proc['pid']:<10} {proc['name'][:24]:<25} {proc['username'][:14]:<15} {proc['cpu_percent']:<8.2f} {proc['memory_percent']:<10.2f} {proc.get('uptime', 'N/A')[:19]:<20}")
    
    # Installed Packages
    print_subsection("Installed Packages")
    package_managers = {
        "apt": "dpkg -l | wc -l",
        "yum": "rpm -qa | wc -l",
        "pacman": "pacman -Q | wc -l",
        "brew": "brew list --formula | wc -l",
        "pip": "pip list | wc -l",
        "pip3": "pip3 list | wc -l"
    }
    
    print("Package Manager Packages Count:")
    for manager, cmd in package_managers.items():
        try:
            count = safe_run_command(cmd)
            if count != "N/A" and count.isdigit():
                print(f"  {manager:<15}: {int(count)-5} packages")  # -5 to account for header lines
        except:
            pass

def get_user_group_info():
    """Collect user and group information"""
    print_section("USER AND GROUP INFORMATION")
    
    # Current User
    print_subsection("Current User")
    print(f"{'Username':<20}: {getpass.getuser()}")
    if hasattr(os, 'getuid'):
        print(f"{'UID':<20}: {os.getuid()}")
        print(f"{'GID':<20}: {os.getgid()}")
        print(f"{'Groups':<20}: {os.getgroups()}")
    
    # All Users and Groups (Unix/Linux)
    if sys.platform != "win32":
        print_subsection("System Users")
        users = safe_run_command("cut -d: -f1 /etc/passwd").split('\n')[:20]  # Limit to 20
        print("First 20 users:")
        for i in range(0, len(users), 5):
            print("  " + ", ".join(users[i:i+5]))
        
        print_subsection("System Groups")
        groups = safe_run_command("cut -d: -f1 /etc/group").split('\n')[:20]  # Limit to 20
        print("First 20 groups:")
        for i in range(0, len(groups), 5):
            print("  " + ", ".join(groups[i:i+5]))

def get_security_info():
    """Collect security-related information"""
    print_section("SECURITY INFORMATION")
    
    # Firewall Status
    print_subsection("Firewall Status")
    if sys.platform.startswith('linux'):
        ufw_status = safe_run_command("ufw status")
        if ufw_status != "N/A":
            print("UFW Status:")
            print(ufw_status[:500])  # Limit output
        else:
            iptables_rules = safe_run_command("iptables -L | wc -l")
            if iptables_rules != "N/A":
                print(f"iptables rules count: {iptables_rules}")
    
    # SSH Information
    print_subsection("SSH Configuration")
    if os.path.exists("/etc/ssh/sshd_config"):
        ssh_config = safe_run_command("grep -v '^#' /etc/ssh/sshd_config | grep -v '^$'")
        if ssh_config != "N/A":
            print("SSH configuration (non-default settings):")
            print(ssh_config[:1000])  # Limit output
    
    # Listening Ports
    print_subsection("Listening Network Ports")
    if sys.platform != "win32":
        listening_ports = safe_run_command("ss -tuln")
    else:
        listening_ports = safe_run_command("netstat -an | findstr LISTENING")
    
    if listening_ports != "N/A":
        print("Active listening ports:")
        lines = listening_ports.split('\n')[:30]  # Limit to 30 lines
        for line in lines:
            if "LISTEN" in line.upper() or "tcp" in line or "udp" in line:
                print(f"  {line}")

def get_environment_info():
    """Collect environment variables and other environment info"""
    print_section("ENVIRONMENT INFORMATION")
    
    # Environment Variables (excluding sensitive ones)
    print_subsection("Environment Variables")
    sensitive_vars = ['password', 'secret', 'token', 'key']
    env_vars = {k: v for k, v in os.environ.items() 
                if not any(sensitive_word in k.lower() for sensitive_word in sensitive_vars)}
    
    # Sort by key for consistent output
    for key in sorted(env_vars.keys())[:50]:  # Limit to 50 vars
        value = env_vars[key]
        # Truncate long values
        if len(value) > 100:
            value = value[:100] + "..."
        print(f"  {key:<30}: {value}")
    
    if len(os.environ) > 50:
        print(f"  ... and {len(os.environ) - 50} more environment variables")

def main():
    """Main function to collect and display all system information"""
    print("=" * 80)
    print("COMPREHENSIVE SYSTEM INFORMATION GATHERING")
    print("=" * 80)
    print(f"{'Timestamp':<20}: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'Script User':<20}: {getpass.getuser()}")
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        print(f"{'Privileges':<20}: Running with root privileges")
    else:
        print(f"{'Privileges':<20}: Running without root privileges (limited information)")
    
    try:
        get_hardware_info()
        get_software_info()
        get_network_info()
        get_application_info()
        get_user_group_info()
        get_security_info()
        get_environment_info()
    except KeyboardInterrupt:
        print("\n\nInformation gathering interrupted by user.")
    except Exception as e:
        print(f"\nError during information gathering: {e}")
    
    print("\n" + "=" * 80)
    print("INFORMATION GATHERING COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    # Check if psutil is installed
    try:
        import psutil
    except ImportError:
        print("Error: psutil module not found. Please install it using:")
        print("  pip install psutil")
        sys.exit(1)
    
    main()
