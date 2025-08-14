
import os
import time
import threading
import psutil
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from antivirus_core import AntivirusEngine, is_system_process, terminate_process, suspend_process, resume_process, get_process_memory_map, scan_process_memory

# 复用核心模块中的日志配置
logger = logging.getLogger(__name__)

class ProcessMonitor(threading.Thread):
    def __init__(self, engine):
        super().__init__(daemon=True)
        self.engine = engine
        self.known_pids = set()
        self._stop_event = threading.Event()
        self._interval = 5
    
    def run(self):
        """Monitor new processes"""
        logger.info("[Process Monitor] Starting new process monitoring...")
        while not self._stop_event.is_set():
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self.known_pids
                
                for pid in new_pids:
                    if self._stop_event.is_set():
                        break
                        
                    try:
                        proc = psutil.Process(pid)
                        exe_path = proc.exe()
                        
                        # 跳过系统进程
                        if is_system_process(pid):
                            continue
                            
                        # Scan process file
                        result, score = self.engine.scan_file(exe_path)
                        
                        if score > 70:
                            logger.warning(f"Detected malicious process launch: PID={pid}, file={exe_path}, reason={result}")
                            
                            # 尝试终止进程
                            if terminate_process(pid):
                                logger.info(f"Successfully terminated process {pid}")
                                
                                # 删除恶意文件
                                if self.engine.delete_file(exe_path, f"Malicious process: {result}"):
                                    logger.info(f"Deleted malicious file: {exe_path}")
                                else:
                                    logger.error(f"Deletion failed: {exe_path}")
                            else:
                                logger.error(f"Unable to terminate process {pid}")
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        logger.debug(f"Process access error: {pid} - {e}")
                        continue
                    except Exception as e:
                        logger.error(f"Error processing process: {pid} - {e}")
                        continue
                        
                self.known_pids = current_pids
                self._stop_event.wait(self._interval)
                
            except Exception as e:
                logger.error(f"Process monitoring exception: {e}")
                self._stop_event.wait(self._interval)
    
    def stop(self):
        """Stop monitoring"""
        self._stop_event.set()
        logger.info("[Process Monitor] Stopping process monitoring...")

class MemoryMonitor(threading.Thread):
    def __init__(self, engine):
        super().__init__(daemon=True)
        self.engine = engine
        self._stop_event = threading.Event()
        self._interval = 30  # 每30秒扫描一次内存
    
    def run(self):
        """Monitor running processes for suspicious memory patterns"""
        logger.info("[Memory Monitor] Starting memory monitoring...")
        while not self._stop_event.is_set():
            try:
                # 获取所有正在运行的进程
                for proc in psutil.process_iter(['pid', 'name']):
                    if self._stop_event.is_set():
                        break
                    
                    pid = proc.pid
                    
                    # 跳过系统进程
                    if is_system_process(pid):
                        continue
                    
                    # 扫描进程内存
                    try:
                        malicious, reason = scan_process_memory(pid, self.engine)
                        if malicious:
                            logger.warning(f"Suspicious memory activity detected in PID {pid} ({proc.name()}): {reason}")
                            
                            # 暂停进程以防止进一步损害
                            if suspend_process(pid):
                                logger.info(f"Suspended process {pid} for investigation")
                                
                                # 尝试终止进程
                                if terminate_process(pid):
                                    logger.info(f"Terminated malicious process {pid}")
                                    
                                    # 获取可执行文件路径并删除
                                    try:
                                        exe_path = proc.exe()
                                        if exe_path and os.path.exists(exe_path):
                                            if self.engine.delete_file(exe_path, f"Malicious memory activity: {reason}"):
                                                logger.info(f"Deleted malicious file: {exe_path}")
                                            else:
                                                logger.error(f"Deletion failed: {exe_path}")
                                    except Exception as e:
                                        logger.error(f"Error getting executable path for PID {pid}: {e}")
                                else:
                                    logger.error(f"Failed to terminate process {pid}")
                            else:
                                logger.error(f"Failed to suspend process {pid}")
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        logger.debug(f"Process memory access error: PID={pid} - {e}")
                    except Exception as e:
                        logger.error(f"Error scanning memory for PID {pid}: {e}")
                
                # 等待下一次扫描
                self._stop_event.wait(self._interval)
                
            except Exception as e:
                logger.error(f"Memory monitoring exception: {e}")
                self._stop_event.wait(self._interval)
    
    def stop(self):
        """Stop monitoring"""
        self._stop_event.set()
        logger.info("[Memory Monitor] Stopping memory monitoring...")

class FileMonitor(FileSystemEventHandler):
    def __init__(self, engine):
        self.engine = engine
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self.record_initial_state()

    def record_initial_state(self):
        monitor_dir = self.engine.monitor_dir
        for root, dirs, files in os.walk(monitor_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if self.engine.is_whitelisted(file_path):
                    continue
                self.engine.record_file_integrity(file_path)

    def on_created(self, event):
        if not event.is_directory and not self._stop_event.is_set():
            file_path = event.src_path
            with self._lock:
                logger.info(f"Detected new file: {file_path}")
                self.engine.record_file_integrity(file_path)
            try:
                # 沙箱扫描优先
                sandbox_matched, sandbox_rule_names = self.engine.sandbox_scan_file(file_path)
                if sandbox_matched:
                    logger.warning(f"⚠️ Sandbox threat: {', '.join(sandbox_rule_names)} (risk level: 100)")
                    # 使用隔离替代删除
                    if self.engine.handle_threat(file_path, f"Sandbox: {', '.join(sandbox_rule_names)}"):
                        logger.info(f"✅ File quarantined: {file_path}")
                    else:
                        logger.error(f"❌ Failed to quarantine file: {file_path}")
                    return
                    
                result, score = self.engine.scan_file(file_path)
                if score > 70:
                    logger.warning(f"⚠️ Threat found: {result} (risk level: {score})")
                    # 使用隔离替代删除
                    if self.engine.handle_threat(file_path, result):
                        logger.info(f"✅ File quarantined: {file_path}")
                    else:
                        logger.error(f"❌ Failed to quarantine file: {file_path}")
                else:
                    logger.info(f"✅ File safe: {file_path}")
            except Exception as e:
                logger.error(f"Error scanning file: {file_path} - {e}")

    def on_modified(self, event):
        file_path = event.src_path  # Always assign file_path
        if event.is_directory or self._stop_event.is_set():
            return
        if self.engine.is_whitelisted(file_path):
            return
        with self._lock:
            try:
                tampered, reason = self.engine.check_file_integrity(file_path)
                if tampered:
                    logger.warning(f"⚠️ File tampering detected: {file_path} - {reason}")
                    # 沙箱扫描优先
                    sandbox_matched, sandbox_rule_names = self.engine.sandbox_scan_file(file_path)
                    if sandbox_matched:
                        logger.warning(f"⚠️ Sandbox threat: {', '.join(sandbox_rule_names)} (risk level: 100)")
                        # 使用隔离替代删除
                        if self.engine.handle_threat(file_path, f"Sandbox: {', '.join(sandbox_rule_names)}"):
                            logger.info(f"✅ File quarantined: {file_path}")
                        else:
                            logger.error(f"❌ Failed to quarantine tampered file: {file_path}")
                        self.engine.record_file_integrity(file_path)
                        return
                        
                    result, score = self.engine.scan_file(file_path)
                    if score > 70:
                        logger.warning(f"⚠️ Tampered file threat: {result} (risk level: {score})")
                        # 使用隔离替代删除
                        if self.engine.handle_threat(file_path, f"Tampered file: {result}"):
                            logger.info(f"✅ File quarantined: {file_path}")
                        else:
                            logger.error(f"❌ Failed to quarantine tampered file: {file_path}")
                    else:
                        logger.info(f"✅ Tampered file safe: {file_path}")
                    self.engine.record_file_integrity(file_path)
                else:
                    self.engine.record_file_integrity(file_path)
                    logger.info(f"File modified: {file_path} - {reason}")
            except Exception as e:
                logger.error(f"Error in file modification event: {file_path} - {e}")
def start_monitoring():
    """Start real-time monitoring service"""
    engine = AntivirusEngine()
    
    # 启动进程监控
    process_monitor = ProcessMonitor(engine)
    process_monitor.start()
    
    # 启动内存监控
    memory_monitor = MemoryMonitor(engine)
    memory_monitor.start()
    
    # 启动文件监控
    file_monitor = FileMonitor(engine)
    observer = Observer()
    observer.schedule(file_monitor, engine.monitor_dir, recursive=True)
    observer.start()
    
    logger.info("Real-time monitoring started")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping monitoring...")
        process_monitor.stop()
        memory_monitor.stop()
        observer.stop()
        observer.join()
        logger.info("Monitoring stopped")

if __name__ == "__main__":

    start_monitoring()
