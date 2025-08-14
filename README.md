# SafetyWen Antivirus 🛡️

SafetyWen is a Python-based Windows antivirus system with real-time monitoring, YARA scanning, memory analysis, file integrity checking, and sandbox isolation. This project is open source and welcomes reference, modification, and extension.

## 🔍 Features

- 🧠 Process Monitoring: Detects and terminates malicious processes
- 🧬 Memory Scanning: Analyzes abnormal process memory behavior
- 📁 File Monitoring: Monitors file additions and modifications for immediate threat isolation
- 🧪 Sandbox Integration: Prioritizes sandboxing for threat analysis
- 🧹 Junk Cleaner: Cleans system junk and temporary files
- 🧰 GUI: Uses tkinter to provide a simple user interface

## ⚙️ Installation

Please install Python 3.8 or later and run the following command to install the necessary packages:

```bash
pip install psutil yara-python watchdog requests pywin32
