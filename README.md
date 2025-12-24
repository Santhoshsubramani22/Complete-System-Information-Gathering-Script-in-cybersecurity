# 🎯 Complete-System-Information-Gathering-Script-in-Cybersecurity 🔐

## 📌 Overview

This Python script is designed to gather and display detailed system information for authorized security assessments. It provides insights into various aspects of a system, including hardware, software, network configuration, user information, security status, and environment variables. The script is intended for educational purposes and security professionals to assess system configurations safely.

**⚠️ Warning**: This tool should only be used on systems you own or have explicit authorization to access.

---

## ✨ Features

- **Hardware Information**: Details on CPU, memory, swap, disk partitions, and more.
- **Software Information**: Information about the operating system, Python environment, and system architecture.
- **Network Information**: IP addresses, network interfaces, statistics, and active network connections.
- **Application Information**: Lists running processes and installed packages.
- **User and Group Information**: Displays current user info, system users, and groups.
- **Security Information**: Firewall status, SSH configuration, and listening network ports.
- **Environment Information**: Displays non-sensitive environment variables and other system settings.

---

## 🛠️ Requirements

- **Python 3.8+** (for running the script)
- **psutil**: To collect system-related information.
  
To install the required Python module:
```bash
pip install psutil
````

---

## 📂 Project Structure

```plaintext
system_info_gathering/
├── system_info_gathering.py  # Main script for gathering system information
└── README.md                 # Project documentation
```

---

## ▶️ How to Run

1. Install required dependencies:

   ```bash
   pip install psutil
   ```

2. Run the script:

   ```bash
   python3 system_info_gathering.py
   ```

3. The script will display system information directly in the console output.

---

## 📝 Example Output

```plaintext
================================================================================
COMPREHENSIVE SYSTEM INFORMATION GATHERING
================================================================================
Timestamp              : 2025-12-22 19:00:12
Script User            : user1
Privileges             : Running without root privileges (limited information)
================================================================================
HARDWARE INFORMATION
================================================================================
--- System Details ---
Manufacturer           : Dell Inc.
Model                  : XPS 13 9300
Serial Number          : 1234567890
--- CPU Details ---
Physical cores         : 4
Logical cores          : 8
Max frequency          : 3200.00 MHz
Current frequency      : 2800.00 MHz
Current usage          : 15%
CPU Usage per Core:
  Core 0: 5%
  Core 1: 10%
  Core 2: 12%
  Core 3: 7%
--- Memory Details ---
Total memory           : 16.00 GB
Available memory       : 8.50 GB
Used memory            : 7.50 GB
Memory percentage      : 47%
...
```

---

## 🔍 How It Works

The script executes various system commands to collect detailed information:

1. **Hardware Information**: Gathers CPU, memory, disk, and other hardware data using `psutil` and `dmidecode`.
2. **Software Information**: Retrieves OS details, Python environment, and kernel info.
3. **Network Information**: Gathers IP configuration, network statistics, and active connections.
4. **Application Information**: Lists running processes and installed packages.
5. **Security Information**: Displays firewall status, SSH settings, and active listening ports.
6. **Environment Information**: Displays non-sensitive environment variables.

All information is printed to the console for easy review.

---

## 🚀 Learning Outcomes

By running this script, you will:

* Understand how to collect and display system information using Python.
* Learn how to use the `psutil` module for system monitoring and management.
* Gain experience in interpreting system configuration and security status.
* Understand the importance of ethical information gathering in security assessments.

---

## 🛡️ Legal & Ethical Disclaimer

* This script should **only** be used on systems you own or have explicit authorization to assess.
* **Do not use** on third-party systems without permission.
* **Do not store or misuse sensitive information** gathered from this script.

---

## 🔜 Possible Enhancements

* **Additional Security Checks**: Incorporate additional security assessments such as vulnerability scanning.
* **Scheduled Execution**: Automate the running of the script via cron jobs for periodic reporting.
* **Output to File**: Redirect the output to a log file for audit purposes.
* **Graphical User Interface (GUI)**: Add a GUI for more user-friendly interactions.

---

## 📜 License

This project is intended for educational and authorized security assessment use only. It is licensed under the **MIT License**.

---

## 💡 Contributions

Feel free to fork this repository, submit issues, or contribute improvements. Contributions are welcome and appreciated.

---

## 🙋‍♂️ Author

This project was created by Santhosh subramani.

---

```
