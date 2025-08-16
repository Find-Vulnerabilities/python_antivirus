
import os
import hashlib
import time
import threading
import json
import math
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import psutil
import codecs
import logging
import sys
import multiprocessing
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
import tempfile
import winshell
import ctypes
from ctypes import wintypes
import win32api
import win32con
import win32process
# 在文件顶部添加新导入
import win32security
import ntsecuritycon as con
from win32com.shell import shell, shellcon
import win32job  # 新增导入
import subprocess
import platform
import urllib.request

# 在配置部分添加隔离区路径
QUARANTINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
# ==================== YARA Support ====================
try:
    import yara
    YARA_SUPPORT = True
except Exception as e:
    YARA_SUPPORT = False
    logging.warning(
        "yara-python library not installed or failed to load: %s\n"
        "If you have installed it via pip but still get errors, it's usually due to missing libyara.dll or dependencies.\n"
        "Solutions:\n"
        "1. Check if Python is 64-bit or 32-bit, libyara.dll must match.\n"
        "2. Download the corresponding wheel from https://github.com/VirusTotal/yara-python/releases, or download libyara.dll from https://github.com/VirusTotal/yara/releases, and place it in Python's DLLs directory or PATH.\n"
        "3. If still not working, try installing with conda (conda install -c conda-forge yara-python) or use official wheels.\n"
        "4. You can ignore this warning, the program will automatically disable YARA detection, other functions are not affected."
        % e
    )
# ================================================

# ==================== Configuration ====================
MONITOR_DIR = os.path.expanduser("~")
DELETION_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deletion_logs")
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "antivirus.log")
MAX_WORKERS = max(2, multiprocessing.cpu_count() - 1)

# Whitelisted paths
WHITELISTED_PATHS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    r"C:\Windows\servicing",
    r"C:\Program Files\Java",
]
WHITELISTED_PATHS = [p.lower() for p in WHITELISTED_PATHS]
# ================================================

# Configure logging
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
if hasattr(sys.stdout, 'buffer'):
    stream_handler = logging.StreamHandler(codecs.getwriter('utf-8')(sys.stdout.buffer))
else:
    stream_handler = logging.StreamHandler(sys.stdout)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[file_handler, stream_handler]
)
logger = logging.getLogger(__name__)

os.makedirs(DELETION_LOG_DIR, exist_ok=True)

# ==================== Utility Functions ====================
def is_system_process(pid):
    """Check if process is a critical system process"""
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe().lower()
        if exe_path.startswith(r"c:\windows\system32") or exe_path.startswith(r"c:\windows\syswow64"):
            return True
        return False
    except Exception:
        return False

def terminate_process(pid):
    """Force terminate a process"""
    try:
        PROCESS_TERMINATE = 0x0001
        handle = win32api.OpenProcess(PROCESS_TERMINATE, False, pid)
        win32process.TerminateProcess(handle, 0)
        win32api.CloseHandle(handle)
        return True
    except Exception as e:
        logger.error(f"Failed to terminate process {pid}: {e}")
        return False

def suspend_process(pid):
    """Suspend a process"""
    try:
        proc = psutil.Process(pid)
        for thread in proc.threads():
            thread_handle = win32api.OpenThread(win32con.THREAD_SUSPEND_RESUME, False, thread.id)
            if thread_handle:
                win32process.SuspendThread(thread_handle)
                win32api.CloseHandle(thread_handle)
        return True
    except Exception as e:
        logger.error(f"Failed to suspend process {pid}: {e}")
        return False

def resume_process(pid):
    """Resume a suspended process"""
    try:
        proc = psutil.Process(pid)
        for thread in proc.threads():
            thread_handle = win32api.OpenThread(win32con.THREAD_SUSPEND_RESUME, False, thread.id)
            if thread_handle:
                win32process.ResumeThread(thread_handle)
                win32api.CloseHandle(thread_handle)
        return True
    except Exception as e:
        logger.error(f"Failed to resume process {pid}: {e}")
        return False

def get_process_memory_map(pid):
    """Get memory map of a process"""
    try:
        proc = psutil.Process(pid)
        return proc.memory_maps()
    except Exception as e:
        logger.error(f"Failed to get memory map for process {pid}: {e}")
        return []

def scan_process_memory(pid, engine):
    """Scan process memory for malicious code"""
    if is_system_process(pid):
        return False, "System process skipped"
    
    try:
        # Get process memory maps
        memory_maps = get_process_memory_map(pid)
        if not memory_maps:
            return False, "No accessible memory regions"
        
        # Check for suspicious memory regions
        suspicious_count = 0
        for mem_map in memory_maps:
            # Correct attribute name to 'perm'
            perms = getattr(mem_map, 'perm', None)
            if perms and 'x' in perms and 'w' in perms:
                logger.warning(f"Suspicious memory region in PID {pid}: {getattr(mem_map, 'path', '')} - {perms}")
                suspicious_count += 1
        
        # If too many suspicious regions, mark as malicious
        if suspicious_count > 3:
            return True, f"Multiple suspicious memory regions found ({suspicious_count})"
        
        return False, "No malicious patterns found"
    except Exception as e:
        logger.error(f"Error scanning memory for process {pid}: {e}")
        return False, f"Scan error: {str(e)}"

def calculate_sha256(file_path):
    """Calculate SHA256 hash of file"""
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating SHA256 hash: {file_path} - {e}")
        return None
# ================================================

class AntivirusEngine:
    def __init__(self):
        self.scan_count = 0
        self.threats_found = 0
        self.deleted_files = []  # Deletion records
        self.deletion_lock = threading.Lock()
        self.load_deletion_list()
        self._stop_event = threading.Event()
        self.monitor_dir = MONITOR_DIR
        self.quarantine_dir = QUARANTINE_DIR
        self._init_quarantine_dir()
        self.file_integrity_records = {}  # {file_path: (size, mtime, hash)}
        self.integrity_lock = threading.Lock()
        self.api_key = None
        self.yara_support = YARA_SUPPORT
        self.yara_rule = None
        if self.yara_support:
            try:
                self._load_yara_rule()
            except Exception as e:
                logger.error(f"Failed to load YARA rules: {e}")
                self.yara_rule = None

    def _load_yara_rule(self):
        """Load YARA rules for various threat detection"""
        if not self.yara_support:
            logger.warning("YARA support not enabled")
            return
        try:
            yara_rules_text = r'''
import "pe"

rule Suspicious_UEFI_Modification_Improved : pe
{
    meta:
        description = "Detects binaries attempting to modify UEFI firmware or EFI variables"
        author = "wenszeyui"
        version = "2.1"
        date = "2025-07-30"
        reference = "UEFI tampering detection"
        severity = "high"

    strings:
        // EFI modification APIs
        $efi1 = "SetFirmwareEnvironmentVariableA" wide ascii
        $efi2 = "SetFirmwareEnvironmentVariableW" wide ascii
        $efi3 = "SetFirmwareEnvironmentVariableEx" wide ascii
        $efi4 = "GetFirmwareEnvironmentVariable" wide ascii

        // EFI paths
        $linux_efi_path = "/sys/firmware/efi/efivars" ascii
        $esp_path = /GLOBALROOT\\Device\\HarddiskVolume[0-9]+\\EFI\\/ wide ascii

        // Bootkit signature
        $bootkit_sig = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }

        // Legitimate update tools
        $legit_uefi1 = "UEFI Firmware Update" wide ascii
        $legit_uefi2 = "BIOS Update Utility" wide ascii

    condition:
        pe.is_pe and
        filesize < 5MB and
        any of ($efi*) and
        not any of ($legit_uefi*) and
        (
            any of ($linux_efi_path, $esp_path, $bootkit_sig) or
            (
                pe.imports("kernel32.dll", "SetFirmwareEnvironmentVariableA") or
                pe.imports("kernel32.dll", "SetFirmwareEnvironmentVariableW") or
                pe.imports("kernel32.dll", "SetFirmwareEnvironmentVariableEx") or
                pe.imports("kernel32.dll", "GetFirmwareEnvironmentVariable")
            )
        )
}


rule Detect_File_Encryption_Behavior {
    strings:
        $crypto1 = "CryptEncrypt" nocase
        $crypto2 = "AES_encrypt" nocase
        $ransom_note = /_decrypt_instructions/i
    condition:
        any of ($crypto*) and $ransom_note
}


rule Detect_File_Extension_Change_Improved : pe
{
    meta:
        description = "Detects binaries that attempt to change file extensions, common in ransomware"
        author = "wennszeyui"
        version = "2.1"
        date = "2025-07-30"
        category = "behavioral"
        maltype = "ransomware or file modifier"
        false_positives = "Some backup utilities may trigger"

    strings:
        // Suspicious extensions
        $ext1 = ".locked" wide ascii
        $ext2 = ".encrypted" wide ascii
        $ext3 = ".enc" wide ascii
        $ext4 = ".pay" wide ascii
        $ext5 = ".deadbolt" wide ascii
        $ext6 = ".crypted" wide ascii
        $ext7 = ".xyz" wide ascii

        // Rename APIs
        $rename1 = "MoveFileA" wide ascii
        $rename2 = "MoveFileW" wide ascii
        $rename3 = "MoveFileExA" wide ascii
        $rename4 = "MoveFileExW" wide ascii

        // Legitimate backup tools
        $legit_backup1 = "Backup Exec" wide ascii
        $legit_backup2 = "Acronis" wide ascii

    condition:
        pe.is_pe and
        not any of ($legit_backup*) and
        any of ($ext*) and
        any of ($rename*) and
        (
            pe.imports("kernel32.dll", "MoveFileA") or
            pe.imports("kernel32.dll", "MoveFileW") or
            pe.imports("kernel32.dll", "MoveFileExA") or
            pe.imports("kernel32.dll", "MoveFileExW")
        )
}


rule Detect_File_Infection_Improved
{
    meta:
        description = "Detects file infectors that append or inject malicious code into PE executables"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-04"
        category = "file-infector"
        maltype = "virus"

    strings:
        $marker1 = "INFECTED_BY_SZ" nocase
        $marker2 = "VIRUS_PAYLOAD" nocase
        $marker3 = { E8 ?? ?? ?? ?? 5B 81 EB }
        $marker4 = { 60 E8 ?? ?? ?? ?? 61 }

    condition:
        pe.is_pe and
        (any of ($marker*) or
         pe.entry_point > pe.sections[pe.number_of_sections - 1].virtual_address)
}


rule Detect_Deletion_of_Critical_C_Drive_Files_Improved
{
    meta:
        description = "Detects attempts to delete critical system files on C:\\ drive"
        author = "szeyui"
        version = "1.1"
        date = "2025-07-04"
        category = "destructive"
        maltype = "wiper / ransomware"

    strings:
        // Deletion APIs
        $delete1 = "DeleteFileA"
        $delete2 = "DeleteFileW"
        $delete3 = "SHFileOperation"
        $delete4 = "RemoveDirectoryA"
        $delete5 = "RemoveDirectoryW"

        // Critical system paths (regex for flexibility)
        $sys1 = /[Cc]:\\\\Windows\\\\System32\\\\ntoskrnl\.exe/
        $sys2 = /[Cc]:\\\\Windows\\\\System32\\\\winload\.exe/
        $sys3 = /[Cc]:\\\\Windows\\\\System32\\\\config\\\\SAM/
        $sys4 = /[Cc]:\\\\Windows\\\\System32\\\\drivers\\\\/
        $sys5 = /[Cc]:\\\\boot\.ini/
        $sys6 = /[Cc]:\\\\Windows\\\\explorer\.exe/
        $sys7 = /[Cc]:\\\\Windows\\\\System32\\\\hal\.dll/

    condition:
        pe.is_pe and
        any of ($delete*) and any of ($sys*)
}

rule Detect_Chat_Log_Stealer_Trojan_With_Facebook_Improved
{
    meta:
        description = "Detects trojans that attempt to steal chat logs from messaging apps including Facebook"
        author = "szeyui"
        version = "1.2"
        date = "2025-07-04"
        category = "infostealer"
        maltype = "chat log stealer"

    strings:
        // Messaging platforms
        $discord = "Discord\\Local Storage\\leveldb"
        $telegram = "Telegram Desktop\\tdata"
        $whatsapp = "WhatsApp\\User Data"
        $skype = "Skype\\My Skype Received Files"
        $wechat = "WeChat Files"
        $qq = "Tencent\\QQ"
        $facebook1 = "Facebook\\Messenger"
        $facebook2 = "messenger.com"
        $facebook3 = "messages/inbox"
        $facebook4 = "threads"

        // Chat content
        $chat1 = "chatlog"
        $chat2 = "message history"
        $chat3 = "conversation"
        $chat4 = "msgstore.db"
        $chat5 = "sqlite3_open"

        // Exfiltration
        $exfil1 = "WinHttpSendRequest"
        $exfil2 = "InternetOpenUrl"
        $exfil3 = "curl"
        $exfil4 = "ftp://"
        $exfil5 = "POST /upload"

        // Decryption / encoding
        $crypto1 = "CryptUnprotectData"
        $crypto2 = "Base64Decode"

    condition:
        pe.is_pe and
        (any of ($discord, $telegram, $whatsapp, $skype, $wechat, $qq, $facebook*)) and
        any of ($chat*) and
        any of ($exfil*) and
        any of ($crypto*)
}

rule Detect_Webcam_Spy_Trojan_Improved
{
    meta:
        description = "Detects trojans that attempt to access, record, and exfiltrate webcam footage"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-04"
        category = "spyware"
        maltype = "webcam stealer"

    strings:
        // Webcam access
        $cam1 = "capCreateCaptureWindowA"
        $cam2 = "capCreateCaptureWindowW"
        $cam3 = "capDriverConnect"
        $cam4 = "capGrabFrame"
        $cam5 = "capFileSaveAs"
        $cam6 = "avicap32.dll"
        $cam7 = "mf.dll"
        $cam8 = "DirectShow"
        $cam9 = "MediaCapture"
        $cam10 = "Windows.Media.Capture"

        // Device identifiers
        $dev1 = "\\\\.\\Global\\usbvideo"
        $dev2 = "vid_"
        $dev3 = "device\\video"
        $dev4 = "CameraCaptureUI"

        // Output formats
        $ext1 = ".avi"
        $ext2 = ".mp4"
        $ext3 = ".jpg"
        $ext4 = ".bmp"
        $ext5 = "webcam_capture"

        // Exfiltration
        $exfil1 = "WinHttpSendRequest"
        $exfil2 = "InternetOpenUrl"
        $exfil3 = "POST /upload"
        $exfil4 = "ftp://"
        $exfil5 = "http://"

    condition:
        pe.is_pe and
        (any of ($cam*) or any of ($dev*)) and
        any of ($ext*) and
        any of ($exfil*)
}


rule Detect_MBR_Modification_Improved
{
    meta:
        description = "Detects binaries attempting to modify the Master Boot Record (MBR)"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-05"
        category = "bootkit"
        maltype = "MBR modifier"

    strings:
        // API functions
        $api1 = "CreateFileA" nocase
        $api2 = "CreateFileW" nocase
        $api3 = "WriteFile" nocase
        $api4 = "DeviceIoControl" nocase
        $api5 = "ReadFile" nocase
        $api6 = "SetFilePointer" nocase

        // Disk access targets
        $disk = /\\\\\.\\(PhysicalDrive|C)([0-9]*)?/ nocase

        // Known malicious MBR patterns
        $bootkit1 = { B8 00 7C 8E D8 8E C0 BE 00 7C BF 00 06 B9 00 02 F3 A5 }
        $bootkit2 = { FA 33 C0 8E D0 BC 00 7C FB 8E D8 E8 00 00 }

    condition:
        pe.is_pe and (
            (any of ($api*) and $disk) or
            (uint16(0x1FE) == 0xAA55 and any of ($bootkit*))
        )
}


rule Detect_GPT_Partition_Modification_Improved
{
    meta:
        description = "Detects binaries attempting to modify GPT partition tables"
        author = "wenszeyui"
        version = "1.1"
        date = "2025-07-05"
        category = "bootkit / persistence"
        maltype = "GPT modifier"

    strings:
        // API functions
        $api1 = "CreateFileA" nocase
        $api2 = "CreateFileW" nocase
        $api3 = "WriteFile" nocase
        $api4 = "DeviceIoControl" nocase
        $api5 = "ReadFile" nocase

        // Disk access targets
        $disk = /\\\\\.\\(PhysicalDrive|Harddisk)[0-9]+(\\Partition[0-9]+)?/ nocase

        // GPT header signature
        $gpt_sig = { 45 46 49 20 50 41 52 54 }  // "EFI PART"

        // Known GUIDs
        $guid1 = { 28 73 2A C1 1F F8 D2 11 BA 4B 00 A0 C9 3E C9 3B }  // EFI System Partition
        $guid2 = { A2 A0 D0 EB E5 B9 33 44 87 C0 68 B6 B7 26 99 C7 }  // Microsoft Reserved

    condition:
        pe.is_pe and
        (any of ($api*) and $disk) and
        (any of ($gpt_sig, $guid1, $guid2))
}


rule Suspicious_JS_Downloader_Improved
{
    meta:
        description = "Detects JavaScript files that download and execute payloads"
        author = "wenszeyui"
        category = "script"
        maltype = "downloader"

    strings:
        // Download behavior
        $url = /https?:\/\/[^\s"]+/ nocase
        $xmlhttp1 = "MSXML2.XMLHTTP" nocase
        $xmlhttp2 = "XMLHttpRequest" nocase
        $stream = "ADODB.Stream" nocase

        // Execution behavior
        $eval = "eval(" nocase
        $wscript = "WScript.Shell" nocase
        $run = ".Run(" nocase
        $powershell = "powershell -" nocase

        // Obfuscation
        $obf1 = "String.fromCharCode" nocase
        $obf2 = "unescape(" nocase

        // File writing
        $write1 = "SaveToFile" nocase
        $write2 = "CreateTextFile" nocase

    condition:
        filesize < 100KB and
        (1 of ($url, $xmlhttp1, $xmlhttp2, $stream, $powershell)) and
        (any of ($eval, $wscript, $run)) and
        (any of ($write1, $write2) or any of ($obf1, $obf2))
}
rule Detect_Script_Persistence_Improved
{
    meta:
        description = "Detects scripts attempting to establish persistence via registry, tasks, or startup folder"
        author = "wenszeyui"
        category = "script"
        maltype = "persistence"

    strings:
        $reg1 = "reg add" nocase
        $reg2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg3 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $schtasks = "schtasks /create" nocase
        $startup = "\\Startup\\" nocase
        $wmi = "__EventFilter" nocase
        $profile = "Microsoft.PowerShell_profile.ps1" nocase

    condition:
        filesize < 100KB and
        (2 of ($reg*, $schtasks, $startup, $wmi, $profile))
}
rule Detect_Script_UEFI_Modification_Improved
{
    meta:
        description = "Detects scripts attempting to modify UEFI firmware or EFI variables"
        author = "szeyui"
        category = "script / firmware"
        maltype = "UEFI tampering"

    strings:
        $wmi = "GetObject(\"winmgmts:" nocase
        $bios = "Win32_BIOS" nocase
        $firmware1 = "SetFirmwareEnvironmentVariable" nocase
        $firmware2 = "SetFirmwareEnvironmentVariableEx" nocase
        $firmware3 = "GetFirmwareEnvironmentVariable" nocase
        $ps = "powershell.exe" nocase
        $efi1 = "\\EFI\\" nocase
        $efi2 = "GLOBALROOT\\Device\\HarddiskVolume" nocase

    condition:
        filesize < 100KB and
        any of ($wmi, $bios, $firmware1, $firmware2, $firmware3, $ps) and
        any of ($efi1, $efi2)
}
rule Detect_Browser_Password_Stealer_Improved
{
    meta:
        description = "Detects attempts to steal and exfiltrate browser passwords"
        author = "szeyui"
        category = "infostealer"
        maltype = "browser stealer"

    strings:
        // Browser password storage
        $chrome = "Chrome\\User Data\\Default\\Login Data"
        $firefox = "signons.sqlite"
        $edge = "Microsoft\\Edge\\User Data"
        $brave = "BraveSoftware\\Brave-Browser\\User Data"
        $opera = "Opera Software\\Opera Stable"

        // Exfiltration
        $exfil1 = "POST /upload"
        $exfil2 = "WinHttpSendRequest"
        $exfil3 = "HttpSendRequest"
        $exfil4 = "InternetOpenUrl"

        // Decryption
        $decrypt = "CryptUnprotectData"

    condition:
        pe.is_pe and
        any of ($chrome, $firefox, $edge, $brave, $opera) and
        any of ($exfil1, $exfil2, $exfil3, $exfil4) and
        $decrypt
}

rule Detect_EFI_Driver_Load_Improved
{
    meta:
        description = "Detects potential EFI driver loading behavior"
        author = "szeyui"
        category = "bootkit"
        maltype = "efi loader"

    strings:
        $efi1 = "\\EFI\\Boot\\bootx64.efi"
        $efi2 = "LoadImage"
        $efi3 = "StartImage"
        $efi4 = "HandleProtocol"
        $efi5 = "InstallProtocolInterface"
        $sig = { 45 46 49 20 50 41 52 54 } // "EFI PART"

    condition:
        // FIX: remove pe.is_64bit, use only pe.machine == pe.MACHINE_AMD64
        (pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
         2 of ($efi*)) or $sig
}

rule Detect_DLL_Injector_Improved
{
    meta:
        description = "Detects potential DLL injection behavior in PE files"
        author = "szeyui"
        category = "trojan"
        maltype = "injector"

    strings:
        $api1 = "OpenProcess"
        $api2 = "VirtualAllocEx"
        $api3 = "WriteProcessMemory"
        $api4 = "CreateRemoteThread"
        $api5 = "LoadLibraryA"
        $api6 = "LoadLibraryW"
        $dll = /\.dll/i

    condition:
        pe.is_pe and
        4 of ($api*) and $dll
}

rule VBScript_FileInfector_SZ_Improved
{
    meta:
        description = "Detects VBScript virus with file infection, destructive behavior, and obfuscation"
        author = "szeyui"
        version = "1.1"
        date = "2025-07-17"
        category = "virus"
        maltype = "vbscript file infector"

    strings:
        // Infection and replication
        $copy1 = "CreateObject(\"Scripting.FileSystemObject\")"
        $copy2 = "CopyFile WScript.ScriptFullName"
        $copy3 = "GetSpecialFolder"
        $copy4 = "WScript.ScriptFullName"

        // Destructive behavior
        $del1 = /Delete(File|Folder)\s+"C:\\\\.*"/
        $del2 = "SetAttr"

        // Dynamic execution / obfuscation
        $exec1 = "Execute("
        $exec2 = "Eval("
        $exec3 = "Chr("
        $exec4 = "Base64Decode"

        // Marker or payload
        $marker = "INFECTED_BY_SZ"

    condition:
        any of ($copy*) and any of ($del*) and any of ($exec*) and $marker
}

rule Detect_Process_Injection_Improved
{
    meta:
        description = "Detects potential process injection behavior in PE files"
        author = "wenszeyui"
        category = "trojan"
        maltype = "process injector"

    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "NtCreateThreadEx"
        $api3 = "WriteProcessMemory"
        $api4 = "VirtualAllocEx"
        $api5 = "QueueUserAPC"
        $api6 = "SetWindowsHookEx"

    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "WriteProcessMemory") or
        pe.imports("kernel32.dll", "CreateRemoteThread") or
        pe.imports("ntdll.dll", "NtCreateThreadEx") or
        3 of ($api*)
}




rule Detect_Self_Modifying_Code_Improved
{
    meta:
        description = "Detects potential self-modifying code behavior in PE files"
        author = "wenszeyui"
        category = "malware"
        maltype = "self-modifying code"

    strings:
        $api1 = "VirtualProtect"
        $api2 = "VirtualAlloc"
        $api3 = "WriteProcessMemory"
        $api4 = "FlushInstructionCache"

    condition:
        pe.is_pe and
        (pe.imports("kernel32.dll", "VirtualProtect") and
         pe.imports("kernel32.dll", "VirtualAlloc") and
         pe.imports("kernel32.dll", "WriteProcessMemory") and
         pe.imports("kernel32.dll", "FlushInstructionCache")) or
        all of ($api*)
}

'''
            self.yara_rule = yara.compile(source=yara_rules_text)
            logger.info("Loaded YARA rules")
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}\nYARA source:\n{yara_rules_text}")
            self.yara_rule = None

    def _init_quarantine_dir(self):
        """创建安全的隔离区目录"""
        try:
            if not os.path.exists(self.quarantine_dir):
                os.makedirs(self.quarantine_dir)
            
            # 设置隔离区权限：只有SYSTEM和Administrators可以访问
            self._set_secure_permissions(self.quarantine_dir)
            logger.info(f"Quarantine directory initialized at {self.quarantine_dir}")
        except Exception as e:
            logger.error(f"Failed to initialize quarantine directory: {e}")

    def _set_secure_permissions(self, path):
        """设置路径的安全权限 - 只允许SYSTEM和Administrators访问"""
        try:
            # 获取当前的安全描述符
            sd = win32security.GetFileSecurity(
                path, 
                win32security.DACL_SECURITY_INFORMATION
            )
        
            # 建立新的 DACL
            dacl = win32security.ACL()
        
            # 添加 SYSTEM 完全控制
            system_sid = win32security.CreateWellKnownSid(
                win32security.WinLocalSystemSid
            )
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, 
                con.FILE_ALL_ACCESS, 
                system_sid
            )
        
            # 添加 Administrators 完全控制
            admin_sid = win32security.CreateWellKnownSid(
                win32security.WinBuiltinAdministratorsSid
            )
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, 
                con.FILE_ALL_ACCESS, 
                admin_sid
            )
        
            # 移除所有繼承的 ACE
            sd.SetSecurityDescriptorControl(
                win32security.SE_DACL_PROTECTED, 
                win32security.SE_DACL_PROTECTED
            )
        
            # 設定新的 DACL
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                path, 
                win32security.DACL_SECURITY_INFORMATION, 
                sd
            )
            logger.info(f"設定安全權限: {path}")
            return True
        except Exception as e:
            logger.error(f"設定安全權限失敗: {e}")
            return False
       
        

    def quarantine_file(self, file_path, reason):
        """将文件移动到隔离区"""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File not found for quarantine: {file_path}")
                return False
                
            # 生成唯一的隔离文件名
            filename = os.path.basename(file_path)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            base, ext = os.path.splitext(filename)
            quarantine_filename = f"{base}_{timestamp}{ext}"
            dest_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # 移动文件到隔离区
            shutil.move(file_path, dest_path)
            
            # 设置隔离文件的权限
            self._set_secure_permissions(dest_path)
            
            # 记录隔离操作
            record = {
                "original_path": file_path,
                "quarantine_path": dest_path,
                "reason": reason,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "quarantined": True
            }
            
            with self.deletion_lock:
                self.deleted_files.append(record)
                self.save_deletion_list()
            
            logger.info(f"Successfully quarantined file: {file_path} -> {dest_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False

    def restore_quarantined_file(self, quarantine_path, original_path=None):
        """从隔离区恢复文件"""
        try:
            if not os.path.exists(quarantine_path):
                logger.warning(f"Quarantined file not found: {quarantine_path}")
                return False
                
            # 如果未提供原始路径，则使用记录中的路径
            if not original_path:
                for record in self.deleted_files:
                    if record.get("quarantine_path") == quarantine_path:
                        original_path = record.get("original_path")
                        break
                
                if not original_path:
                    logger.error(f"Original path not found for quarantined file: {quarantine_path}")
                    return False
            
            # 恢复文件
            shutil.move(quarantine_path, original_path)
            
            # 更新记录
            with self.deletion_lock:
                self.deleted_files = [r for r in self.deleted_files 
                                     if r.get("quarantine_path") != quarantine_path]
                self.save_deletion_list()
            
            logger.info(f"Successfully restored file: {quarantine_path} -> {original_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore quarantined file {quarantine_path}: {e}")
            return False
    
    
    def is_whitelisted(self, file_path):
        """Check if file is in whitelisted path"""
        try:
            file_path = os.path.abspath(file_path).lower()
            for whitelist_path in WHITELISTED_PATHS:
                if file_path.startswith(whitelist_path.lower()):
                    return True
            return False
        except Exception as e:
            logger.error(f"Error checking whitelist for {file_path}: {e}")
            return False
    
    def stop(self):
        """Stop all scanning"""
        self._stop_event.set()
        logger.info("Antivirus engine stopped")
    
    def load_deletion_list(self):
        """Load deletion records"""
        deletion_file = os.path.join(DELETION_LOG_DIR, "deletion_log.json")
        if os.path.exists(deletion_file):
            try:
                with open(deletion_file, 'r', encoding='utf-8') as f:
                    self.deleted_files = json.load(f)
                logger.info(f"Successfully loaded deletion records, total {len(self.deleted_files)} files")
            except Exception as e:
                logger.error(f"Failed to load deletion records: {e}")
                self.deleted_files = []
    
    def save_deletion_list(self):
        """Save deletion records"""
        deletion_file = os.path.join(DELETION_LOG_DIR, "deletion_log.json")
        with self.deletion_lock:
            try:
                with open(deletion_file, 'w', encoding='utf-8') as f:
                    json.dump(self.deleted_files, f, indent=2, ensure_ascii=False)
                logger.info("Deletion records saved successfully")
            except Exception as e:
                logger.error(f"Failed to save deletion records: {e}")
    
    def scan_file(self, file_path):
        """Scan single file"""
        self.scan_count += 1

        if self._stop_event.is_set():
            return "Scan stopped", 0

        if not os.path.exists(file_path):
            return "File does not exist", 0

        if self.is_whitelisted(file_path):
            return "Whitelisted file", 0

        # Sandbox scan first
        sandbox_matched, sandbox_rule_names = self.sandbox_scan_file(file_path)
        if sandbox_matched:
            self.threats_found += 1
            return f"Sandbox match: {', '.join(sandbox_rule_names)}", 100

        # YARA scan for any rule match
        yara_matched, yara_rule_names = self.yara_scan_file(file_path)
        if yara_matched:
            self.threats_found += 1
            return f"YARA match: {', '.join(yara_rule_names)}", 100

        # File extension risk assessment
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        # Initial risk assessment
        if ext in ['.exe', '.bat', '.cmd', '.vbs', '.js', '.jar', '.dll', '.sys']:
            result = "High risk file type"
            score = 30
        else:
            result = "Safe"
            score = 0

        # Heuristic analysis
        suspicious_score = 0
        if suspicious_score > 50:
            score = max(score, suspicious_score)
            result = f"Suspicious file (score: {suspicious_score})"
        
        if score > 70:
            self.threats_found += 1
        
        return result, score
    
    def calculate_sha256(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            return file_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating SHA256 hash: {file_path} - {e}")
            return None
    
    def delete_file(self, file_path, reason):
        """Delete file and record deletion info"""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"File does not exist, cannot delete: {file_path}")
                return False
                
            # Calculate file hash for record
            file_hash = self.calculate_sha256(file_path)
            if file_hash is None:
                file_hash = "Hash calculation failed"

            # Record deletion info
            record = {
                "original_path": file_path,
                "reason": reason,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "file_hash": file_hash,
                "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                "deleted": True
            }
            
            # Attempt to delete file
            try:
                os.remove(file_path)
                logger.info(f"Successfully deleted file: {file_path}")
                record["deleted"] = True
            except Exception as e:
                logger.error(f"Failed to delete file: {file_path} - {e}")
                record["deleted"] = False
                record["error"] = str(e)
            
            # Save deletion record
            with self.deletion_lock:
                self.deleted_files.append(record)
                self.save_deletion_list()
                
            return record["deleted"]
        except Exception as e:
            logger.error(f"Error during file deletion: {file_path} - {e}")
            return False
    
    def yara_scan_file(self, file_path):
        """Scan file with loaded YARA rules"""
        if not self.yara_support or not self.yara_rule:
            return False, None
        try:
            matches = self.yara_rule.match(file_path)
            if matches:
                rule_names = [m.rule for m in matches]
                return True, rule_names
            return False, None
        except Exception as e:
            logger.error(f"YARA scan error: {file_path} - {e}")
            return False, None

    def sandbox_scan_file(self, file_path):
        """沙箱扫描：YARA规则+行为分析（Windows Sandbox）"""
        if not self.yara_support or not self.yara_rule:
            return False, None
        try:
            matches = self.yara_rule.match(file_path)
            sandbox_rules = [
                "Suspicious_UEFI_Modification",
                "Detect_File_Extension_Change",
                "Detect_File_Infection",
                "Detect_Deletion_of_Critical_C_Drive_Files",
                "Detect_Process_Injection",
                "Detect_Self_Modifying_Code",
                "Detect_Code_Cave"
            ]
            hit_rules = [m.rule for m in matches if m.rule in sandbox_rules]
            if hit_rules:
                # 行为沙箱：在Windows Sandbox中运行可疑文件（仅限可执行文件）
                _, ext = os.path.splitext(file_path)
                if ext.lower() in ['.exe', '.bat', '.cmd']:
                    run_in_windows_sandbox(file_path)
                    # TODO: 可扩展为监控API调用、文件/注册表/网络行为
                return True, hit_rules
            return False, None
        except Exception as e:
            logger.error(f"Sandbox scan error: {file_path} - {e}")
            return False, None

    # ==================== File Integrity Functions ====================
    def record_file_integrity(self, file_path):
        """Record file integrity information (size, mtime, hash)"""
        try:
            if not os.path.isfile(file_path):
                return

            stat = os.stat(file_path)
            file_hash = self.calculate_sha256(file_path)

            with self.integrity_lock:
                self.file_integrity_records[file_path] = {
                    'size': stat.st_size,
                    'mtime': stat.st_mtime,
                    'hash': file_hash
                }
        except Exception as e:
            logger.error(f"Failed to record file integrity: {file_path} - {e}")
    
    def check_file_integrity(self, file_path):
        """Check if file has been tampered with"""
        try:
            if not os.path.exists(file_path):
                return False, "File does not exist"
                
            with self.integrity_lock:
                if file_path not in self.file_integrity_records:
                    return False, "No baseline recorded"
                
                baseline = self.file_integrity_records[file_path]
            
            current_stat = os.stat(file_path)
            current_hash = self.calculate_sha256(file_path)
            
            if (current_stat.st_size != baseline['size'] or 
                current_stat.st_mtime != baseline['mtime'] or
                current_hash != baseline['hash']):
                return True, "File has been tampered with"
            
            return False, "File unchanged"
        except Exception as e:
            logger.error(f"File integrity check failed: {file_path} - {e}")
            return False, f"Check error: {str(e)}"
    # ================================================
    
    # ==================== Junk Cleaner ====================
    def clean_junk_files(self, include_temp=True, include_zero_byte=True, include_recycle_bin=True):
        """Clean up junk files and return statistics"""
        cleaned_files = 0
        freed_space = 0
        
        # Clean temporary files
        if include_temp:
            temp_cleaned, temp_freed = self.clean_temp_files()
            cleaned_files += temp_cleaned
            freed_space += temp_freed
        
        # Clean zero-byte files
        if include_zero_byte:
            zero_cleaned, zero_freed = self.clean_zero_byte_files()
            cleaned_files += zero_cleaned
            freed_space += zero_freed
        
        # Clean recycle bin
        if include_recycle_bin:
            recycle_cleaned, recycle_freed = self.clean_recycle_bin()
            cleaned_files += recycle_cleaned
            freed_space += recycle_freed
        
        return cleaned_files, freed_space
    
    def clean_temp_files(self):
        """Clean temporary files from common locations"""
        cleaned = 0
        freed = 0

        temp_dirs = [
            tempfile.gettempdir(),
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp'),
            os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Temp')
        ]

        # Add browser cache paths
        browser_cache_paths = [
            os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Cache"),
            os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Media Cache"),
            os.path.expanduser("~/AppData/Local/Microsoft/Edge/User Data/Default/Cache"),
            os.path.expanduser("~/AppData/Local/Mozilla/Firefox/Profiles/*/cache2"),
            os.path.expanduser("~/AppData/Local/Opera Software/Opera Stable/Cache"),
        ]

        temp_dirs.extend(browser_cache_paths)

        for temp_dir in temp_dirs:
            if not temp_dir or not os.path.exists(temp_dir):
                continue
            try:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            file_size = os.path.getsize(file_path)
                            os.remove(file_path)
                            cleaned += 1
                            freed += file_size
                        except Exception as e:
                            logger.warning(f"Could not delete temp file {file_path}: {e}")
            except Exception as e:
                logger.error(f"Error cleaning temp dir {temp_dir}: {e}")
        return cleaned, freed

    def clean_zero_byte_files(self):
        """Clean zero-byte TXT and PDF files"""
        cleaned = 0
        freed = 0

        search_dirs = [
            os.path.expanduser("~"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
        ]

        for search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue

            try:
                for root, dirs, files in os.walk(search_dir):
                    for file in files:
                        if file.lower().endswith(('.txt', '.pdf')):
                            file_path = os.path.join(root, file)
                            try:
                                if os.path.getsize(file_path) == 0:
                                    os.remove(file_path)
                                    cleaned += 1
                            except Exception as e:
                                logger.warning(f"Could not delete zero-byte file {file_path}: {e}")
            except Exception as e:
                logger.error(f"Error cleaning zero-byte files in {search_dir}: {e}")
        return cleaned, freed

    def clean_recycle_bin(self):
        """Empty the recycle bin and return statistics"""
        try:
            items = list(winshell.recycle_bin())
            total_size = sum(item.original_size() for item in items)
            total_files = len(items)
            rb = winshell.recycle_bin()
            rb.empty(confirm=False, show_progress=False, sound=False)
            return total_files, total_size
        except Exception as e:
            logger.error(f"Error emptying recycle bin: {e}")
            return 0, 0
    # ================================================

    def handle_threat(self, file_path, reason):
        """Handle detected threat: quarantine first, fallback to delete."""
        # Check if already quarantined
        for record in self.deleted_files:
            if record.get("original_path") == file_path and record.get("quarantined"):
                logger.info(f"File already quarantined: {file_path}")
                return True

        # Try to quarantine
        if self.quarantine_file(file_path, reason):
            return True

        # If quarantine fails, try to delete
        return self.delete_file(file_path, reason)

def is_windows_sandbox_available():
    """Check if Windows Sandbox is available/enabled."""
    system = platform.system()
    if system != "Windows":
        return False
    sandbox_path = r"C:\Windows\System32\WindowsSandbox.exe"
    return os.path.exists(sandbox_path)

def enable_windows_sandbox():
    """Try to enable Windows Sandbox via DISM (requires admin)."""
    try:
        # Enable Windows Sandbox feature (Windows 10/11 Pro/Enterprise/Education)
        subprocess.run(
            ["dism.exe", "/Online", "/Enable-Feature", "/FeatureName:Containers-DisposableClientVM", "/All", "/NoRestart"],
            check=True, shell=True
        )
        return True
    except Exception as e:
        logger.error(f"Failed to enable Windows Sandbox: {e}")
        return False

def download_windows_sandbox_installer():
    """Provide instructions or download link for Windows Sandbox."""
    # Windows Sandbox 不是独立下载包，需通过系统功能开启
    # 这里只弹窗提示
    messagebox.showerror(
        "Windows Sandbox Not Available",
        "Windows Sandbox is not available on your system.\n"
        "Please enable it via 'Turn Windows features on or off' and check 'Windows Sandbox'.\n"
        "Requires Windows 10/11 Pro/Enterprise/Education."
    )

def run_in_windows_sandbox(file_path):
    """Run the given file in Windows Sandbox."""
    if not is_windows_sandbox_available():
        # 尝试自动启用
        if not enable_windows_sandbox():
            download_windows_sandbox_installer()
            return False

    # 生成 .wsb 配置文件
    wsb_content = f"""<Configuration>
<MappedFolders>
    <MappedFolder>
        <HostFolder>{os.path.dirname(file_path)}</HostFolder>
        <ReadOnly>false</ReadOnly>
    </MappedFolder>
</MappedFolders>
<LogonCommand>
    <Command>{os.path.basename(file_path)}</Command>
</LogonCommand>
</Configuration>
"""
    temp_wsb = os.path.join(tempfile.gettempdir(), "antivirus_sandbox.wsb")
    with open(temp_wsb, "w", encoding="utf-8") as f:
        f.write(wsb_content)

    try:
        subprocess.Popen([r"C:\Windows\System32\WindowsSandbox.exe", temp_wsb], shell=False)
        logger.info(f"Started Windows Sandbox for {file_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to start Windows Sandbox: {e}")
        return False

class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SafetyWen Antivirus")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        self.engine = AntivirusEngine()
        self.scan_thread = None
        self.memory_scan_thread = None
        self._scan_running = False
        self._cleanup_running = False
        self._memory_scan_running = False
        self.threat_list = []  # Store detected threats
        
        self.create_widgets()
        self.load_deletion_list()
        
        # Clean up resources when window closes
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_widgets(self):
        """Create GUI interface"""
        style = ttk.Style()
        style.configure('TNotebook.Tab', padding=(10, 5))
        style.configure('TButton', padding=5)
        style.configure('TLabelFrame', padding=10)
        
        self.tab_control = ttk.Notebook(self.root)
        
        # Scan tab
        self.tab_scan = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_scan, text='Scan')
        
        # Deletion log tab
        self.tab_deletion_log = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_deletion_log, text='Deletion Log')
        
        # Cleanup tab
        self.tab_cleanup = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_cleanup, text='Cleanup')
        
        # Memory scan tab
        self.tab_memory = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_memory, text='Memory Scan')
        
        self.tab_control.pack(expand=1, fill="both")
        
        self.build_scan_tab()
        self.build_deletion_log_tab()
        self.build_cleanup_tab()
        self.build_memory_tab()
        
        # Status bar
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(fill="x", padx=10, pady=5)
        self.status_label = ttk.Label(self.status_bar, text="Ready")
        self.status_label.pack(side="left")
        self.scan_progress = ttk.Progressbar(self.status_bar, mode="determinate")
        self.scan_progress.pack(side="right", fill="x", expand=True, padx=5)
        self.scan_progress.pack_forget()  # Hidden by default

        self.tab_quarantine = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_quarantine, text='Quarantine')
        self.build_quarantine_tab()

    
    def build_quarantine_tab(self):
        """构建隔离区管理界面"""
        frame = ttk.LabelFrame(self.tab_quarantine, text="Quarantined Files")
        frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("original_path", "reason", "timestamp")
        self.quarantine_tree = ttk.Treeview(
            frame, 
            columns=columns, 
            show="headings",
            selectmode="browse"
        )
        
        # 配置列
        self.quarantine_tree.heading("original_path", text="Original Path")
        self.quarantine_tree.heading("reason", text="Reason")
        self.quarantine_tree.heading("timestamp", text="Timestamp")
        
        self.quarantine_tree.column("original_path", width=300, stretch=tk.YES)
        self.quarantine_tree.column("reason", width=150)
        self.quarantine_tree.column("timestamp", width=150)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(
            frame, 
            orient="vertical", 
            command=self.quarantine_tree.yview
        )
        self.quarantine_tree.configure(yscrollcommand=scrollbar.set)
        
        self.quarantine_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 操作按钮
        btn_frame = ttk.Frame(self.tab_quarantine)
        btn_frame.pack(fill="x", padx=10, pady=10)
        
        self.restore_btn = ttk.Button(
            btn_frame, 
            text="Restore Selected", 
            command=self.restore_quarantined_file
        )
        self.restore_btn.pack(side="left", padx=5)
        
        self.delete_btn = ttk.Button(
            btn_frame, 
            text="Delete Permanently", 
            command=self.delete_quarantined_file
        )
        self.delete_btn.pack(side="left", padx=5)
        
        self.refresh_quarantine_btn = ttk.Button(
            btn_frame, 
            text="Refresh List", 
            command=self.load_quarantine_list
        )
        self.refresh_quarantine_btn.pack(side="right", padx=5)
        
        # 加载隔离区列表
        self.load_quarantine_list()
    
    def load_quarantine_list(self):
        """加载隔离区文件列表"""
        self.quarantine_tree.delete(*self.quarantine_tree.get_children())
        for record in self.engine.deleted_files:
            if record.get("quarantined"):
                self.quarantine_tree.insert(
                    "", "end",
                    values=(
                        record.get("original_path", ""),
                        record.get("reason", ""),
                        record.get("timestamp", "")
                    ),
                    tags=(record.get("quarantine_path", ""),)
                )
    
    def restore_quarantined_file(self):
        """恢复选中的隔离文件"""
        selected = self.quarantine_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a file to restore.")
            return
            
        item = self.quarantine_tree.item(selected[0])
        quarantine_path = item['tags'][0] if item['tags'] else None
        original_path = item['values'][0] if item['values'] else None
        
        if not quarantine_path or not original_path:
            messagebox.showerror("Error", "Failed to get file information.")
            return
            
        # 检查原始路径是否已存在文件
        if os.path.exists(original_path):
            choice = messagebox.askyesno("File Exists", 
                                        "Original path already exists. Overwrite?",
                                        icon=messagebox.WARNING)
            if not choice:
                return
                
        # 恢复文件
        if self.engine.restore_quarantined_file(quarantine_path, original_path):
            messagebox.showinfo("Success", "File restored successfully.")
            self.load_quarantine_list()
        else:
            messagebox.showerror("Error", "Failed to restore file.")
    
    def delete_quarantined_file(self):
        """永久删除隔离文件"""
        selected = self.quarantine_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a file to delete.")
            return
            
        item = self.quarantine_tree.item(selected[0])
        quarantine_path = item['tags'][0] if item['tags'] else None
        
        if not quarantine_path:
            messagebox.showerror("Error", "Failed to get file information.")
            return
            
        # 确认操作
        if not messagebox.askyesno("Confirm", 
                                  "This will permanently delete the file. Continue?",
                                  icon=messagebox.WARNING):
            return
            
        # 删除文件
        try:
            os.remove(quarantine_path)
            
            # 更新记录
            with self.engine.deletion_lock:
                self.engine.deleted_files = [r for r in self.engine.deleted_files 
                                           if r.get("quarantine_path") != quarantine_path]
                self.engine.save_deletion_list()
            
            messagebox.showinfo("Success", "File permanently deleted.")
            self.load_quarantine_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete file: {e}")
    
    def build_scan_tab(self):
        """Build scan tab"""
        dir_frame = ttk.LabelFrame(self.tab_scan, text="Scan Directory")
        dir_frame.pack(fill="x", padx=10, pady=5)
        
        self.dir_entry = ttk.Entry(dir_frame)
        self.dir_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        self.dir_entry.insert(0, os.path.expanduser("~"))
        
        browse_btn = ttk.Button(dir_frame, text="Browse...", command=self.browse_directory)
        browse_btn.pack(side="right", padx=5, pady=5)
        
        # Scan options
        options_frame = ttk.LabelFrame(self.tab_scan, text="Scan Options")
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.deep_scan_var = tk.BooleanVar(value=True)
        deep_scan_cb = ttk.Checkbutton(options_frame, text="Deep Scan", variable=self.deep_scan_var)
        deep_scan_cb.pack(side="left", padx=5, pady=5)
        
        # Scan buttons
        btn_frame = ttk.Frame(self.tab_scan)
        btn_frame.pack(fill="x", padx=10, pady=10)
        
        self.scan_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=5)
        
        self.stop_scan_btn = ttk.Button(btn_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_scan_btn.pack(side="left", padx=5)
        
        # Handle threats button
        self.handle_threats_btn = ttk.Button(btn_frame, text="Handle Threats", command=self.handle_threats, state=tk.DISABLED)
        self.handle_threats_btn.pack(side="right", padx=5)
        
        # Scan results
        result_frame = ttk.LabelFrame(self.tab_scan, text="Scan Results")
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=15)
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.result_text.config(state=tk.DISABLED)
        
        # Configure text tags
        self.result_text.tag_configure("danger", foreground="red", font=('TkDefaultFont', 10, 'bold'))
        self.result_text.tag_configure("warning", foreground="orange")
        self.result_text.tag_configure("safe", foreground="green")
        self.result_text.tag_configure("info", foreground="blue")

    def build_deletion_log_tab(self):
        """Build deletion log tab"""
        list_frame = ttk.LabelFrame(self.tab_deletion_log, text="Deleted File Records")
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("original_path", "reason", "timestamp", "deleted")
        self.deletion_tree = ttk.Treeview(
            list_frame, 
            columns=columns, 
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        self.deletion_tree.heading("original_path", text="Original Path")
        self.deletion_tree.heading("reason", text="Reason")
        self.deletion_tree.heading("timestamp", text="Timestamp")
        self.deletion_tree.heading("deleted", text="Deleted")
        
        self.deletion_tree.column("original_path", width=300, stretch=tk.YES)
        self.deletion_tree.column("reason", width=150)
        self.deletion_tree.column("timestamp", width=150)
        self.deletion_tree.column("deleted", width=80)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(
            list_frame, 
            orient="vertical", 
            command=self.deletion_tree.yview
        )
        self.deletion_tree.configure(yscrollcommand=scrollbar.set)
        
        self.deletion_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Deletion log operation buttons
        btn_frame = ttk.Frame(self.tab_deletion_log)
        btn_frame.pack(fill="x", padx=10, pady=10)
        
        self.refresh_btn = ttk.Button(
            btn_frame, 
            text="Refresh List", 
            command=self.load_deletion_list
        )
        self.refresh_btn.pack(side="right", padx=5)
        
    def build_cleanup_tab(self):
        """Build cleanup tab"""
        # Cleanup options
        options_frame = ttk.LabelFrame(self.tab_cleanup, text="Cleanup Options")
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.clean_temp_var = tk.BooleanVar(value=True)
        clean_temp_cb = ttk.Checkbutton(
            options_frame, 
            text="Clean Temporary Files", 
            variable=self.clean_temp_var
        )
        clean_temp_cb.pack(anchor="w", padx=5, pady=2)
        
        self.clean_zero_var = tk.BooleanVar(value=True)
        clean_zero_cb = ttk.Checkbutton(
            options_frame, 
            text="Clean Zero-Byte Files (TXT/PDF)", 
            variable=self.clean_zero_var
        )
        clean_zero_cb.pack(anchor="w", padx=5, pady=2)
        
        self.clean_recycle_var = tk.BooleanVar(value=True)
        clean_recycle_cb = ttk.Checkbutton(
            options_frame, 
            text="Empty Recycle Bin", 
            variable=self.clean_recycle_var
        )
        clean_recycle_cb.pack(anchor="w", padx=5, pady=2)
        
        # Cleanup button
        btn_frame = ttk.Frame(self.tab_cleanup)
        btn_frame.pack(fill="x", padx=10, pady=10)
        
        self.cleanup_btn = ttk.Button(
            btn_frame, 
            text="Start Cleanup", 
            command=self.start_cleanup
        )
        self.cleanup_btn.pack(side="left", padx=5)
        
        # Cleanup log
        log_frame = ttk.LabelFrame(self.tab_cleanup, text="Cleanup Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.cleanup_log = scrolledtext.ScrolledText(log_frame, height=15)
        self.cleanup_log.pack(fill="both", expand=True, padx=5, pady=5)
        self.cleanup_log.config(state=tk.DISABLED)
        
        # Configure text tags
        self.cleanup_log.tag_configure("success", foreground="green")
        self.cleanup_log.tag_configure("info", foreground="blue")
        self.cleanup_log.tag_configure("warning", foreground="orange")
        self.cleanup_log.tag_configure("error", foreground="red")

    def build_memory_tab(self):
        """Build memory scan tab"""
        # Memory scan description
        desc_frame = ttk.LabelFrame(self.tab_memory, text="Memory Scan")
        desc_frame.pack(fill="x", padx=10, pady=5)
        
        desc_label = ttk.Label(
            desc_frame, 
            text="Memory scanning checks running processes for suspicious activities.\n"
                 "It can detect malicious code injections, rootkits, and other in-memory threats.\n"
                 "Click 'Scan Memory Now' to start a manual scan."
        )
        desc_label.pack(padx=10, pady=10)
        
        # Memory scan buttons
        btn_frame = ttk.Frame(self.tab_memory)
        btn_frame.pack(fill="x", padx=10, pady=10)
        
        self.scan_memory_btn = ttk.Button(
            btn_frame, 
            text="Scan Memory Now", 
            command=self.start_memory_scan
        )
        self.scan_memory_btn.pack(side="left", padx=5)
        
        # Memory scan log
        log_frame = ttk.LabelFrame(self.tab_memory, text="Memory Scan Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.memory_log = scrolledtext.ScrolledText(log_frame, height=15)
        self.memory_log.pack(fill="both", expand=True, padx=5, pady=5)
        self.memory_log.config(state=tk.DISABLED)
        
        # Configure text tags
        self.memory_log.tag_configure("danger", foreground="red", font=('TkDefaultFont', 10, 'bold'))
        self.memory_log.tag_configure("warning", foreground="orange")
        self.memory_log.tag_configure("safe", foreground="green")
        self.memory_log.tag_configure("info", foreground="blue")

    def browse_directory(self):
        """Browse directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)

    def log_message(self, text_widget, message, tag=None):
        """Log message to text widget"""
        text_widget.config(state=tk.NORMAL)
        text_widget.insert(tk.END, message + "\n", tag)
        text_widget.see(tk.END)
        text_widget.config(state=tk.DISABLED)

    def update_status(self, message):
        """Update status bar"""
        self.status_label.config(text=message)
        self.root.update_idletasks()

    def start_scan(self):
        """Start scan"""
        scan_dir = self.dir_entry.get()
        if not scan_dir or not os.path.isdir(scan_dir):
            messagebox.showerror("Error", "Please select a valid scan directory")
            return
            
        if self._scan_running:
            messagebox.showwarning("Warning", "Scan already in progress")
            return
            
        self._scan_running = True
        self.engine.scan_count = 0
        self.engine.threats_found = 0
        self.threat_list = []  # Clear threat list
        self.engine._stop_event.clear()
        
        # Clear results
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.log_message(self.result_text, f"Starting scan directory: {scan_dir}", "info")
        self.result_text.config(state=tk.DISABLED)
        
        # Update UI state
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_scan_btn.config(state=tk.NORMAL)
        self.handle_threats_btn.config(state=tk.DISABLED)
        self.scan_progress.pack(side="right", fill="x", expand=True, padx=5)
        self.scan_progress["value"] = 0
        self.update_status("Scanning...")
        
        # Start scan thread
        self.scan_thread = threading.Thread(
            target=self.perform_scan,
            args=(scan_dir,),
            daemon=True
        )
        self.scan_thread.start()
        
        # Start progress update
        self._update_scan_progress()

    def stop_scan(self):
        """Stop scan"""
        if not self._scan_running:
            return
            
        self.engine._stop_event.set()
        self.update_status("Stopping scan...")
        self.log_message(self.result_text, "User requested scan stop...", "info")

    def _update_scan_progress(self):
        """Update scan progress"""
        if self._scan_running:
            current_value = self.scan_progress["value"]
            if current_value < 90:  # Prevent reaching 100% until scan completes
                self.scan_progress["value"] = current_value + 1
            self.root.after(100, self._update_scan_progress)

    def perform_scan(self, scan_dir):
        """Perform scan"""
        start_time = time.time()
        total_files = 0
        scanned_files = 0

        try:
            # Count total files for progress display
            if self.deep_scan_var.get():
                for root, dirs, files in os.walk(scan_dir):
                    total_files += len(files)
            else:
                total_files = len(os.listdir(scan_dir))

            # Actual scan
            if self.deep_scan_var.get():
                for root, dirs, files in os.walk(scan_dir):
                    if self.engine._stop_event.is_set():
                        break
                    for file in files:
                        if self.engine._stop_event.is_set():
                            break
                        file_path = os.path.join(root, file)
                        try:
                            # Sandbox scan first
                            sandbox_matched, sandbox_rule_names = self.engine.sandbox_scan_file(file_path)
                            if sandbox_matched:
                                result, score = f"Sandbox match: {', '.join(sandbox_rule_names)}", 100
                            else:
                                result, score = self.engine.scan_file(file_path)
                        except Exception as e:
                            result, score = f"Scan error: {e}", 0
                        scanned_files += 1

                        log_msg = f"[{scanned_files}/{total_files}] {file_path} -> {result} (Risk level: {score})"
                        tag = "danger" if score > 70 else "warning" if score > 50 else "safe"
                        self.log_message(self.result_text, log_msg, tag)
                        
                        # Record high-risk files
                        if score > 70:
                            self.threat_list.append({
                                "path": file_path,
                                "reason": result,
                                "score": score
                            })

            else:
                for file in os.listdir(scan_dir):
                    if self.engine._stop_event.is_set():
                        break
                    file_path = os.path.join(scan_dir, file)
                    if os.path.isfile(file_path):
                        try:
                            # Sandbox scan first
                            sandbox_matched, sandbox_rule_names = self.engine.sandbox_scan_file(file_path)
                            if sandbox_matched:
                                result, score = f"Sandbox match: {', '.join(sandbox_rule_names)}", 100
                            else:
                                result, score = self.engine.scan_file(file_path)
                        except Exception as e:
                            result, score = f"Scan error: {e}", 0
                        scanned_files += 1

                        tag = "danger" if score > 70 else "warning" if score > 50 else "safe"
                        self.log_message(
                            self.result_text,
                            f"[{scanned_files}/{total_files}] {file_path} -> {result} (Risk level: {score})",
                            tag
                        )
                        
                        # Record high-risk files
                        if score > 70:
                            self.threat_list.append({
                                "path": file_path,
                                "reason": result,
                                "score": score
                            })

        except Exception as e:
            self.log_message(self.result_text, f"Scan exception: {e}", "danger")
            logger.error(f"Scan exception: {e}")
        finally:
            self._scan_running = False
            self.engine._stop_event.clear()
            duration = time.time() - start_time
            
            # Display scan summary
            self.log_message(self.result_text, "\n===== Scan Summary =====", "info")
            self.log_message(self.result_text, f"Files scanned: {scanned_files}", "info")
            self.log_message(self.result_text, f"Threats found: {len(self.threat_list)}", 
                            "danger" if self.threat_list else "safe")
            self.log_message(self.result_text, f"Time taken: {duration:.2f} seconds", "info")
            
            if self.threat_list:
                self.log_message(self.result_text, "\nThreats detected. Click 'Handle Threats' to remove them.", "danger")
                self.handle_threats_btn.config(state=tk.NORMAL)
            else:
                self.log_message(self.result_text, "\nNo threats detected. Your system is safe.", "safe")
            
            self.scan_progress["value"] = 100
            self.update_status(f"Scan completed, files scanned: {scanned_files}, threats found: {len(self.threat_list)}")
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_scan_btn.config(state=tk.DISABLED)
            self.scan_progress.pack_forget()

    def handle_threat(self, file_path, reason):
        """处理检测到的威胁 - 使用隔离替代删除"""
        # 检查是否已在隔离区
        for record in self.engine.deleted_files:
            if record.get("original_path") == file_path and record.get("quarantined"):
                logger.info(f"File already quarantined: {file_path}")
                return True

        # 隔离文件
        if self.engine.quarantine_file(file_path, reason):
            return True

        # 如果隔离失败，尝试删除
        return self.engine.delete_file(file_path, reason)

    def handle_threats(self):
        """Start threat handling in a separate thread"""
        if not self.threat_list:
            messagebox.showinfo("Info", "No threats to handle.")
            return
        self.handle_threats_btn.config(state=tk.DISABLED)
        self.scan_btn.config(state=tk.DISABLED)
        self.update_status("Handling threats...")
        threading.Thread(target=self.perform_threat_handling, daemon=True).start()

    def perform_threat_handling(self):
        """处理威胁 - 使用隔离替代删除"""
        try:
            total_threats = len(self.threat_list)
            handled_count = 0
            
            self.log_message(self.result_text, "\n===== Threat Handling Started =====", "info")
            
            for i, threat in enumerate(self.threat_list):
                if self.engine._stop_event.is_set():
                                       break
                    
                file_path = threat["path"]
                reason = threat["reason"]
                
                # 更新进度
                self.scan_progress["value"] = i + 1
                self.update_status(f"Handling threats: {i+1}/{total_threats}")
                
                # 处理威胁 - 使用隔离
                try:
                    if self.engine.handle_threat(file_path, reason):
                        self.log_message(self.result_text, f"✅ Quarantined: {file_path} ({reason})", "safe")
                        handled_count += 1
                    else:
                        self.log_message(self.result_text, f"❌ Failed to handle threat: {file_path}", "danger")
                except Exception as e:
                    self.log_message(self.result_text, f"❌ Error handling {file_path}: {e}", "danger")
            
            # 显示处理摘要
            self.log_message(self.result_text, "\n===== Threat Handling Summary =====", "info")
            self.log_message(self.result_text, f"Threats handled: {handled_count}/{total_threats}", 
                            "safe" if handled_count == total_threats else "danger")
            
            # 清除威胁列表
            self.threat_list = []
            
            # 更新状态
            self.update_status(f"Threat handling completed: {handled_count}/{total_threats} threats quarantined")
            
        except Exception as e:
            self.log_message(self.result_text, f"Threat handling error: {e}", "danger")
            logger.error(f"Threat handling error: {e}")
        finally:
            self._scan_running = False
            self.scan_btn.config(state=tk.NORMAL)
            self.handle_threats_btn.config(state=tk.DISABLED)
            self.scan_progress.pack_forget()

    def load_deletion_list(self):
        """Load deleted file records"""
        self.engine.load_deletion_list()
        self.deletion_tree.delete(*self.deletion_tree.get_children())
        for record in self.engine.deleted_files:
            self.deletion_tree.insert(
                "", "end",
                values=(
                    record.get("original_path", ""),
                    record.get("reason", ""),
                    record.get("timestamp", ""),
                    "Yes" if record.get("deleted", False) else "No"
                )
            )
            
    def start_cleanup(self):
        """Start cleanup process"""
        if self._cleanup_running:
            messagebox.showwarning("Warning", "Cleanup already in progress")
            return
            
        # Confirm before proceeding
        if not messagebox.askyesno("Confirm Cleanup", 
                                  "This operation will delete files permanently. Are you sure you want to proceed?"):
            return
            
        # Clear cleanup log
        self.cleanup_log.config(state=tk.NORMAL)
        self.cleanup_log.delete(1.0, tk.END)
        self.cleanup_log.config(state=tk.DISABLED)
        
        self._cleanup_running = True
        self.cleanup_btn.config(state=tk.DISABLED)
        self.update_status("Cleaning up junk files...")
        
        # Get cleanup options
        clean_temp = self.clean_temp_var.get()
        clean_zero = self.clean_zero_var.get()
        clean_recycle = self.clean_recycle_var.get()
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(
            target=self.perform_cleanup,
            args=(clean_temp, clean_zero, clean_recycle),
            daemon=True
        )
        cleanup_thread.start()

    def perform_cleanup(self, clean_temp, clean_zero, clean_recycle):
        """Perform the cleanup operation"""
        try:
            # Log selected options
            self.log_cleanup_message("Starting cleanup process...", "info")
            self.log_cleanup_message(f"Options: Temporary Files: {'Yes' if clean_temp else 'No'}, "
                                    f"Zero-Byte Files: {'Yes' if clean_zero else 'No'}, "
                                    f"Recycle Bin: {'Yes' if clean_recycle else 'No'}", "info")
            
            # Perform cleanup
            cleaned_files, freed_space = self.engine.clean_junk_files(
                include_temp=clean_temp,
                include_zero_byte=clean_zero,
                include_recycle_bin=clean_recycle
            )
            
            # Format freed space
            freed_mb = freed_space / (1024 * 1024)
            
            # Show results
            self.log_cleanup_message(f"Cleanup completed! Removed {cleaned_files} files, freed {freed_mb:.2f} MB", "success")
            messagebox.showinfo("Cleanup Complete", 
                              f"Cleanup completed successfully!\n\n"
                              f"Files removed: {cleaned_files}\n"
                              f"Space freed: {freed_mb:.2f} MB")
        except Exception as e:
            self.log_cleanup_message(f"Cleanup failed: {e}", "error")
            messagebox.showerror("Cleanup Error", f"An error occurred during cleanup: {e}")
        finally:
            self._cleanup_running = False
            self.cleanup_btn.config(state=tk.NORMAL)
            self.update_status("Ready")
            
    def log_cleanup_message(self, message, tag="info"):
        """Log message to cleanup log"""
        self.cleanup_log.config(state=tk.NORMAL)
        self.cleanup_log.insert(tk.END, message + "\n", tag)
        self.cleanup_log.see(tk.END)
        self.cleanup_log.config(state=tk.DISABLED)
    
    def start_memory_scan(self):
        """Start manual memory scan"""
        if self._memory_scan_running:
            messagebox.showwarning("Warning", "Memory scan already in progress")
            return
            
        self._memory_scan_running = True
        self.scan_memory_btn.config(state=tk.DISABLED)
        self.log_message(self.memory_log, "Starting memory scan...", "info")
        self.update_status("Scanning memory...")
        
        # Start memory scan thread
        memory_scan_thread = threading.Thread(
            target=self.perform_memory_scan,
            daemon=True
        )
        memory_scan_thread.start()

    def perform_memory_scan(self):
        """Perform memory scan of all running processes"""
        try:
            # Clear memory log
            self.memory_log.config(state=tk.NORMAL)
            self.memory_log.delete(1.0, tk.END)
            self.memory_log.config(state=tk.DISABLED)
            
            self.log_message(self.memory_log, "===== Memory Scan Started =====", "info")
            
            # Get all processes
            processes = list(psutil.process_iter(['pid', 'name']))
            total_processes = len(processes)
            scanned_count = 0
            threats_found = 0
            
            for i, proc in enumerate(processes):
                if self.engine._stop_event.is_set():
                    break
                    
                pid = proc.pid
                name = proc.name()
                
                # Update status
                self.update_status(f"Scanning memory: {i+1}/{total_processes} - {name}")
                
                # Skip system processes
                if is_system_process(pid):
                    self.log_message(self.memory_log, f"Skipped system process: PID={pid}, Name={name}", "info")
                    scanned_count += 1
                    continue
                
                # Scan process memory
                try:
                    malicious, reason = scan_process_memory(pid, self.engine)
                    if malicious:
                        self.log_message(self.memory_log, f"⚠️ Threat detected: PID={pid}, Name={name}, Reason={reason}", "danger")
                        threats_found += 1
                    else:
                        self.log_message(self.memory_log, f"✅ Process clean: PID={pid}, Name={name}", "safe")
                    
                    scanned_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.log_message(self.memory_log, f"⚠️ Access denied: PID={pid}, Name={name}", "warning")
                except Exception as e:
                    self.log_message(self.memory_log, f"❌ Error scanning PID={pid}: {str(e)}", "danger")
            
            # Display scan summary
            self.log_message(self.memory_log, "\n===== Memory Scan Summary =====", "info")
            self.log_message(self.memory_log, f"Processes scanned: {scanned_count}/{total_processes}", "info")
            self.log_message(self.memory_log, f"Threats found: {threats_found}", 
                            "danger" if threats_found else "safe")
            
            # Update status
            self.update_status(f"Memory scan completed, threats found: {threats_found}")
            
        except Exception as e:
            self.log_message(self.memory_log, f"Memory scan error: {e}", "danger")
            logger.error(f"Memory scan error: {e}")
        finally:
            self._memory_scan_running = False
            self.scan_memory_btn.config(state=tk.NORMAL)

    def on_close(self):
        """Clean up when closing window"""
        if self._scan_running:
            if not messagebox.askyesno("Confirm", "Scan in progress, are you sure you want to quit?"):
                return
        
        self.engine.stop()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusGUI(root)

    root.mainloop()
    root.mainloop()
