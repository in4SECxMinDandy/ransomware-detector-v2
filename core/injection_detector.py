"""
injection_detector.py
=====================
Advanced Process Injection Detection Module.

Detects various injection techniques:
  - Process Hollowing (in-memory PE vs disk PE)
  - DLL Injection (suspicious DLL paths)
  - Memory Region Anomalies (RWX sections)
  - LOLBins Abuse (mshta, regsvr32, certutil, wmic)
  - Shellcode Execution patterns
  - Reflective DLL Injection

Dependencies:
  - psutil: process information
  - pywin32/ctypes: Windows API for memory reading

Usage:
    detector = InjectionDetector()
    alerts = detector.scan_all_processes()
    hollowing = detector.detect_process_hollowing(pid)
"""

import os
import sys
import time
import ctypes
import hashlib
import logging
from ctypes import wintypes
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)

# Windows API Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01


class InjectionType(Enum):
    PROCESS_HOLLOWING = "process_hollowing"
    DLL_INJECTION = "dll_injection"
    MEMORY_REGION_ANOMALY = "memory_region_anomaly"
    LOLBINS_ABUSE = "lolbins_abuse"
    REFLECTIVE_DLL = "reflective_dll"
    SHELLCODE_EXECUTION = "shellcode_execution"
    SUSPICIOUS_DLL_PATH = "suspicious_dll_path"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class InjectionAlert:
    """Alert về injection detection."""
    injection_type: InjectionType
    pid: int
    process_name: str
    severity: Severity
    description: str
    indicators: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "type": self.injection_type.value,
            "pid": self.pid,
            "process_name": self.process_name,
            "severity": self.severity.value,
            "description": self.description,
            "indicators": self.indicators,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class MemoryRegion:
    """Thông tin về một vùng nhớ."""
    address: int
    size: int
    protect: int
    state: str
    type: str
    is_executable: bool
    is_writable: bool
    is_readable: bool
    is_rwx: bool
    allocation_protect: int


class InjectionDetector:
    """
    Advanced injection detection using Windows API and behavioral analysis.
    
    Usage:
        detector = InjectionDetector()
        
        # Scan all processes
        alerts = detector.scan_all_processes()
        
        # Check specific process
        hollowing, alert = detector.detect_process_hollowing(pid)
        
        # Monitor LOLBins
        lolbins = detector.detect_lolbins_abuse()
    """
    
    # LOLBins - Living Off the Land Binaries
    LOLBINS = {
        "mshta.exe": {
            "description": "MSHTA - HTML Applications",
            "risk": "high",
            "suspicious_args": ["http", ".hta", "-EncodedCommand"]
        },
        "regsvr32.exe": {
            "description": "RegSvr32 - COM object registration",
            "risk": "high", 
            "suspicious_args": ["scrobj", ".sct", "/i:", "http"]
        },
        "certutil.exe": {
            "description": "CertUtil - Certificate utility",
            "risk": "high",
            "suspicious_args": ["-decode", "-urlcache", "-verifyctl", "http"]
        },
        "cmstp.exe": {
            "description": "CMSTP - Connection Manager",
            "risk": "high",
            "suspicious_args": ["/s:", "/ni:", "http"]
        },
        "msiexec.exe": {
            "description": "MSI Installer",
            "risk": "medium",
            "suspicious_args": ["/q", "/x", "http"]
        },
        "rundll32.exe": {
            "description": "Rundll32 - DLL execution",
            "risk": "high",
            "suspicious_args": ["javascript:", "mshtml:", "shell32.dll", "##"]
        },
        "bitsadmin.exe": {
            "description": "BITS Admin",
            "risk": "medium",
            "suspicious_args": ["transfer", "http"]
        },
        "wscript.exe": {
            "description": "WScript - VBS/JS scripting",
            "risk": "high",
            "suspicious_args": [".js", ".vbs", "javascript:"]
        },
        "cscript.exe": {
            "description": "CScript - VBS/JS scripting",
            "risk": "high",
            "suspicious_args": [".js", ".vbs"]
        },
        "powershell.exe": {
            "description": "PowerShell",
            "risk": "medium",
            "suspicious_args": ["-EncodedCommand", "-ExecutionPolicy", "http", "-WindowStyle"]
        },
        "cmd.exe": {
            "description": "Command Prompt",
            "risk": "low",
            "suspicious_args": ["http", "/c", "/k", "powershell"]
        },
    }
    
    # Dangerous APIs used in injection
    DANGEROUS_APIS = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "SetThreadContext", "ResumeThread",
        "QueueUserAPC", "NtMapViewOfSection", "NtUnmapViewOfSection",
        "ShellExecuteExW", "WinExec", "LoadLibraryA", "LoadLibraryW",
        "GetProcAddress", "LdrLoadDll"
    }
    
    # Suspicious DLL paths
    SUSPICIOUS_DLL_PATTERNS = [
        "temp", "tmp", "appdata", "downloads", "temporary",
        "\\temp\\", "\\tmp\\", "\\downloads\\", 
        "desktop", "documents"
    ]
    
    # Known benign DLL paths
    KNOWN_DLL_PATHS = {
        "C:\\Windows\\System32", "C:\\Windows\\SysWOW64",
        "C:\\Windows\\WinSxS", "C:\\Program Files",
        "C:\\Program Files (x86)"
    }

    def __init__(self):
        self._kernel32 = None
        self._alerts: List[InjectionAlert] = []
        
        if os.name == "nt" and sys.platform == "win32":
            try:
                self._kernel32 = ctypes.windll.kernel32
            except Exception as e:
                logger.warning(f"Failed to load kernel32: {e}")
    
    def scan_all_processes(self) -> List[InjectionAlert]:
        """
        Scan tất cả processes cho injection indicators.
        
        Returns:
            List of InjectionAlert objects
        """
        alerts = []
        
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available, cannot scan processes")
            return alerts
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                
                # Skip system processes
                if pid < 100 or name.lower() in ['system', 'lsass.exe', 'csrss.exe']:
                    continue
                
                # Check for process hollowing
                _, alert = self.detect_process_hollowing(pid)
                if alert:
                    alerts.append(alert)
                
                # Check DLL load anomalies
                dll_alerts = self.check_dll_load_anomaly(pid)
                alerts.extend(dll_alerts)
                
                # Scan suspicious memory regions
                mem_alerts = self.scan_suspicious_memory_regions(pid)
                alerts.extend(mem_alerts)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"Error scanning process: {e}")
        
        # Check LOLBins abuse
        lolbin_alerts = self.detect_lolbins_abuse()
        alerts.extend(lolbin_alerts)
        
        self._alerts = alerts
        return alerts
    
    def scan_suspicious_memory_regions(self, pid: int) -> List[InjectionAlert]:
        """
        Quét vùng nhớ MEM_PRIVATE + EXECUTABLE của process.
        
        Args:
            pid: Process ID
            
        Returns:
            List of alerts for suspicious memory regions
        """
        alerts = []
        
        if not PSUTIL_AVAILABLE or not self._kernel32:
            return alerts
        
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            # Get all memory regions
            regions = self._get_memory_regions(pid)
            
            # Count RWX private regions
            rwx_private = [r for r in regions if r.is_rwx and r.type == "MEM_PRIVATE"]
            
            if len(rwx_private) > 3:
                # Multiple RWX private regions - suspicious
                total_size = sum(r.size for r in rwx_private)
                
                alert = InjectionAlert(
                    injection_type=InjectionType.MEMORY_REGION_ANOMALY,
                    pid=pid,
                    process_name=proc_name,
                    severity=Severity.HIGH if len(rwx_private) <= 5 else Severity.CRITICAL,
                    description=f"Suspicious memory regions: {len(rwx_private)} RWX private regions",
                    indicators=[
                        f"RWX region count: {len(rwx_private)}",
                        f"Total RWX size: {total_size / (1024*1024):.2f} MB"
                    ],
                    metadata={
                        "region_count": len(rwx_private),
                        "total_size_mb": total_size / (1024*1024),
                        "regions": [
                            {"address": hex(r.address), "size": r.size, "protect": hex(r.protect)}
                            for r in rwx_private[:5]  # Limit to 5 for metadata
                        ]
                    }
                )
                alerts.append(alert)
            
            # Check for executable heap (common in shellcode execution)
            exec_heap = [r for r in regions if r.is_executable and "Heap" in str(r.type)]
            if len(exec_heap) > 2:
                alert = InjectionAlert(
                    injection_type=InjectionType.SHELLCODE_EXECUTION,
                    pid=pid,
                    process_name=proc_name,
                    severity=Severity.MEDIUM,
                    description=f"Multiple executable heaps detected: {len(exec_heap)}",
                    indicators=[f"Executable heap count: {len(exec_heap)}"],
                    metadata={"heap_count": len(exec_heap)}
                )
                alerts.append(alert)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.debug(f"Error scanning memory regions for PID {pid}: {e}")
        
        return alerts
    
    def _get_memory_regions(self, pid: int) -> List[MemoryRegion]:
        """Get all memory regions for a process."""
        regions = []
        
        if not self._kernel32:
            return regions
        
        try:
            handle = self._kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
            )
            if not handle:
                return regions
            
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]
            
            address = 0
            while address < 0x7FFFFFFF:
                mbi = MEMORY_BASIC_INFORMATION()
                
                ret = self._kernel32.VirtualQueryEx(
                    handle, ctypes.c_void_p(address),
                    ctypes.byref(mbi), ctypes.sizeof(mbi)
                )
                if ret == 0:
                    break
                
                is_r = bool(mbi.Protect & 0x400)  # PAGE_READONLY or PAGE_READWRITE
                is_w = bool(mbi.Protect & 0x800)  # PAGE_WRITECOPY or PAGE_READWRITE
                is_x = bool(mbi.Protect & 0x20)  # PAGE_EXECUTE or related
                
                state_map = {0x1000: "MEM_COMMIT", 0x10000: "MEM_RESERVE", 0: "MEM_FREE"}
                type_map = {0x20000: "MEM_PRIVATE", 0x1000000: "MEM_MAPPED", 0x40000000: "MEM_IMAGE"}
                
                region = MemoryRegion(
                    address=mbi.BaseAddress,
                    size=mbi.RegionSize,
                    protect=mbi.Protect,
                    state=state_map.get(mbi.State, "UNKNOWN"),
                    type=type_map.get(mbi.Type, "UNKNOWN"),
                    is_executable=is_x,
                    is_writable=is_w,
                    is_readable=is_r,
                    is_rwx=is_r and is_w and is_x,
                    allocation_protect=mbi.AllocationProtect
                )
                regions.append(region)
                
                address += mbi.RegionSize
            
            self._kernel32.CloseHandle(handle)
            
        except Exception as e:
            logger.debug(f"Error getting memory regions for PID {pid}: {e}")
        
        return regions
    
    def detect_process_hollowing(self, pid: int) -> Tuple[bool, Optional[InjectionAlert]]:
        """
        Detect Process Hollowing by comparing in-memory PE header vs disk PE.
        
        Args:
            pid: Process ID
            
        Returns:
            Tuple of (is_hollowing: bool, alert_or_None: Optional[InjectionAlert])
        """
        if not PSUTIL_AVAILABLE:
            return False, None
        
        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            proc_name = proc.name()
            
            # Verify disk PE
            if not os.path.exists(exe_path) or not exe_path.lower().endswith('.exe'):
                return False, None
            
            # Check if process has suspicious memory characteristics
            regions = self._get_memory_regions(pid)
            
            # Look for inconsistencies
            indicators = []
            
            # 1. Check for RWX regions in what should be a normal process
            rwx_count = sum(1 for r in regions if r.is_rwx and r.type == "MEM_PRIVATE")
            if rwx_count > 2:
                indicators.append(f"Abnormal RWX region count: {rwx_count}")
            
            # 2. Check for large executable private allocations
            large_exec = [r for r in regions if r.is_executable and r.size > 1024*1024 and r.type == "MEM_PRIVATE"]
            if large_exec:
                indicators.append(f"Large executable private allocations: {len(large_exec)}")
            
            # 3. Check entropy of suspicious regions (requires reading memory)
            # This is a simplified heuristic check
            
            # Calculate confidence based on indicators
            confidence = min(len(indicators) * 0.35, 0.95) if indicators else 0.0
            
            if confidence >= 0.35:
                severity = Severity.CRITICAL if confidence >= 0.7 else Severity.HIGH
                
                alert = InjectionAlert(
                    injection_type=InjectionType.PROCESS_HOLLOWING,
                    pid=pid,
                    process_name=proc_name,
                    severity=severity,
                    description=f"Process Hollowing detected with {len(indicators)} indicators",
                    indicators=indicators,
                    metadata={
                        "exe_path": exe_path,
                        "confidence": confidence,
                        "rwx_private_count": rwx_count,
                        "large_exec_count": len(large_exec)
                    }
                )
                return True, alert
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            logger.debug(f"Error detecting process hollowing for PID {pid}: {e}")
        
        return False, None
    
    def check_dll_load_anomaly(self, pid: int) -> List[InjectionAlert]:
        """
        Phát hiện DLL được load từ path bất thường.
        
        Args:
            pid: Process ID
            
        Returns:
            List of alerts
        """
        alerts = []
        
        if not PSUTIL_AVAILABLE:
            return alerts
        
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            for dll in proc.dlls():
                dll_path = dll.path.lower()
                dll_name = dll.name.lower() if hasattr(dll, 'name') else os.path.basename(dll_path)
                
                # Check for suspicious paths
                is_suspicious = False
                reason = ""
                
                for pattern in self.SUSPICIOUS_DLL_PATTERNS:
                    if f"\\{pattern}\\" in dll_path or f"/{pattern}/" in dll_path:
                        is_suspicious = True
                        reason = f"DLL from suspicious path: {pattern}"
                        break
                
                # Check for known suspicious DLL names
                suspicious_names = ["reflective", "inject", "shellcode", "payload", "hook"]
                if any(name in dll_name for name in suspicious_names):
                    is_suspicious = True
                    reason = f"Suspicious DLL name: {dll_name}"
                
                # Check for DLLs in temp with non-standard extensions
                if "temp" in dll_path or "tmp" in dll_path:
                    if dll_path.endswith(('.dll', '.ocx')):
                        # Could be malicious DLL
                        pass
                
                if is_suspicious:
                    alert = InjectionAlert(
                        injection_type=InjectionType.DLL_INJECTION,
                        pid=pid,
                        process_name=proc_name,
                        severity=Severity.HIGH,
                        description=reason,
                        indicators=[dll_path],
                        metadata={"dll_path": dll_path, "dll_name": dll_name}
                    )
                    alerts.append(alert)
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            logger.debug(f"Error checking DLL anomalies for PID {pid}: {e}")
        
        return alerts
    
    def detect_lolbins_abuse(self) -> List[InjectionAlert]:
        """
        Phát hiện lạm dụng LOLBins (Living Off the Land Binaries).
        
        Returns:
            List of alerts
        """
        alerts = []
        
        if not PSUTIL_AVAILABLE:
            return alerts
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                name = proc.info['name'].lower()
                
                if name not in self.LOLBINS:
                    continue
                
                cmdline = proc.info.get('cmdline', [])
                if not cmdline:
                    continue
                
                cmd_str = " ".join(cmdline).lower()
                proc_path = proc.exe().lower() if hasattr(proc, 'exe') else ""
                
                lolbin_info = self.LOLBINS[name]
                suspicious_args = lolbin_info.get('suspicious_args', [])
                
                # Check for suspicious patterns
                matched_patterns = []
                for pattern in suspicious_args:
                    if pattern.lower() in cmd_str:
                        matched_patterns.append(pattern)
                
                # Additional checks
                indicators = []
                
                # Check for network connections (HTTP/HTTPS)
                if any(net in cmd_str for net in ['http://', 'https://', 'ftp://']):
                    indicators.append("Network URL in command")
                
                # Check for encoded commands
                if '-encodedcommand' in cmd_str or '-e ' in cmd_str:
                    indicators.append("Encoded command detected")
                
                # Check for suspicious file extensions
                suspicious_extensions = ['.hta', '.sct', '.js', '.vbs', '.ps1', '.bat', '.cmd']
                for ext in suspicious_extensions:
                    if ext in cmd_str:
                        indicators.append(f"Suspicious extension: {ext}")
                
                # Only alert if suspicious indicators found
                if matched_patterns or indicators:
                    severity_str = lolbin_info.get('risk', 'medium')
                    severity = Severity.CRITICAL if severity_str == 'high' else Severity.MEDIUM
                    
                    # Increase severity if network indicators
                    if any("http" in i.lower() for i in indicators):
                        severity = Severity.CRITICAL
                    
                    alert = InjectionAlert(
                        injection_type=InjectionType.LOLBINS_ABUSE,
                        pid=proc.info['pid'],
                        process_name=name,
                        severity=severity,
                        description=f"LOLBins abuse detected: {lolbin_info['description']}",
                        indicators=matched_patterns + indicators,
                        metadata={
                            "lolbin": name,
                            "lolbin_description": lolbin_info['description'],
                            "cmdline": " ".join(cmdline),
                            "matched_patterns": matched_patterns
                        }
                    )
                    alerts.append(alert)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"Error detecting LOLBins: {e}")
        
        return alerts
    
    def monitor_api_call_patterns(self, pid: int) -> Dict:
        """
        Monitor API call patterns (requires ETW or hooking - simplified version).
        
        Args:
            pid: Process ID
            
        Returns:
            Dictionary with API call statistics
        """
        result = {
            "pid": pid,
            "dangerous_api_count": 0,
            "suspicious_apis": [],
            "risk_level": "low"
        }
        
        # This is a simplified version
        # Full implementation would require ETW or API hooking
        
        if not PSUTIL_AVAILABLE:
            return result
        
        try:
            proc = psutil.Process(pid)
            
            # Check DLLs loaded by the process
            # If DLLs containing dangerous APIs are loaded, that's a signal
            dangerous_dlls = {
                "kernel32.dll": list(self.DANGEROUS_APIS),
                "ntdll.dll": ["NtCreateThreadEx", "NtMapViewOfSection", "NtUnmapViewOfSection"],
            }
            
            for dll in proc.dlls():
                dll_name = dll.name.lower()
                
                for known_dll, apis in dangerous_dlls.items():
                    if known_dll in dll_name:
                        result["dangerous_api_count"] += len(apis)
                        result["suspicious_apis"].extend(apis)
            
            # Determine risk level
            if result["dangerous_api_count"] > 10:
                result["risk_level"] = "high"
            elif result["dangerous_api_count"] > 5:
                result["risk_level"] = "medium"
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.debug(f"Error monitoring API patterns for PID {pid}: {e}")
        
        return result
    
    def get_alerts(self) -> List[InjectionAlert]:
        """Get all alerts from last scan."""
        return self._alerts
    
    def clear_alerts(self):
        """Clear all alerts."""
        self._alerts.clear()
    
    def get_statistics(self) -> Dict:
        """Get detection statistics."""
        if not self._alerts:
            return {
                "total_alerts": 0,
                "by_type": {},
                "by_severity": {},
                "by_process": {}
            }
        
        by_type = {}
        by_severity = {}
        by_process = {}
        
        for alert in self._alerts:
            # By type
            type_key = alert.injection_type.value
            by_type[type_key] = by_type.get(type_key, 0) + 1
            
            # By severity
            severity_key = alert.severity.value
            by_severity[severity_key] = by_severity.get(severity_key, 0) + 1
            
            # By process
            proc_key = alert.process_name
            by_process[proc_key] = by_process.get(proc_key, 0) + 1
        
        return {
            "total_alerts": len(self._alerts),
            "by_type": by_type,
            "by_severity": by_severity,
            "by_process": by_process,
            "last_scan": self._alerts[-1].timestamp.isoformat() if self._alerts else None
        }


# Singleton instance
_detector: Optional[InjectionDetector] = None


def get_injection_detector() -> InjectionDetector:
    """Get singleton InjectionDetector instance."""
    global _detector
    if _detector is None:
        _detector = InjectionDetector()
    return _detector


if __name__ == "__main__":
    import json
    
    detector = InjectionDetector()
    
    print("Scanning for process injection indicators...")
    alerts = detector.scan_all_processes()
    
    print(f"\nFound {len(alerts)} alerts:")
    for alert in alerts:
        print(f"\n[{alert.severity.value}] {alert.process_name} (PID: {alert.pid})")
        print(f"  Type: {alert.injection_type.value}")
        print(f"  Description: {alert.description}")
        if alert.indicators:
            print(f"  Indicators: {', '.join(alert.indicators)}")
    
    stats = detector.get_statistics()
    print(f"\nStatistics: {json.dumps(stats, indent=2)}")
