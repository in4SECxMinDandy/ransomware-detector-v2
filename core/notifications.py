"""
notifications.py
================
Windows Toast Notifications Module cho ransomware alerts.

Hỗ trợ:
  - Windows 10/11 Toast Notifications (win10toast)
  - Fallback sang console print nếu không có thư viện
  - Audio alerts (tùy chọn)
  - Notification history

Usage:
    from core.notifications import NotificationManager
    
    notifier = NotificationManager()
    notifier.notify(
        title="Ransomware Detected!",
        message="Mass encryption detected",
        severity="critical"
    )
"""

import os
import sys
import threading
import platform
from typing import Optional, Callable, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Try to import win10toast, fallback gracefully
try:
    from win10toast import ToastNotifier
    WIN10TOAST_AVAILABLE = True
except ImportError:
    WIN10TOAST_AVAILABLE = False

# Fallback: try plyer
try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False


class Severity(Enum):
    """Mức độ nghiêm trọng."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Icon paths cho từng mức độ (nếu có)
SEVERITY_ICONS = {
    Severity.LOW: "info",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "warning",
    Severity.CRITICAL: "error",
}

# Sound files cho từng mức độ
SEVERITY_SOUNDS = {
    Severity.LOW: None,
    Severity.MEDIUM: "SystemAsterisk",
    Severity.HIGH: "SystemExclamation",
    Severity.CRITICAL: "SystemHand",  # Critical stop sound
}


@dataclass
class Notification:
    """Notification object."""
    title: str
    message: str
    severity: Severity
    timestamp: datetime = field(default_factory=datetime.now)
    icon: str = ""
    sound: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
        }


class NotificationManager:
    """
    Manager cho Windows Toast Notifications.

    Usage:
        notifier = NotificationManager()
        notifier.notify("Alert", "Message", "critical")
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._toaster = None
        self._history: List[Notification] = []
        self._enabled = True
        self._sound_enabled = True
        self._callback: Optional[Callable[[Notification], None]] = None

        # Initialize toaster
        if WIN10TOAST_AVAILABLE:
            try:
                self._toaster = ToastNotifier()
            except Exception:
                self._toaster = None
        elif PLYER_AVAILABLE:
            self._toaster = "plyer"
        else:
            self._toaster = None

    @property
    def is_available(self) -> bool:
        """Kiểm tra notification có sẵn không."""
        return self._toaster is not None

    @property
    def history(self) -> List[Notification]:
        """Lấy notification history."""
        return self._history.copy()

    @property
    def enabled(self) -> bool:
        """Notifications enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        """Set notifications enabled."""
        self._enabled = value

    @property
    def sound_enabled(self) -> bool:
        """Sound enabled."""
        return self._sound_enabled

    @sound_enabled.setter
    def sound_enabled(self, value: bool):
        """Set sound enabled."""
        self._sound_enabled = value

    def set_callback(self, callback: Callable[[Notification], None]):
        """Set callback cho notification."""
        self._callback = callback

    def notify(
        self,
        title: str,
        message: str,
        severity: str = "medium",
        duration: float = 5.0,
        **kwargs
    ) -> bool:
        """
        Gửi notification.

        Args:
            title: Tiêu đề notification
            message: Nội dung
            severity: "low", "medium", "high", "critical"
            duration: Thời gian hiển thị (giây)

        Returns:
            True nếu gửi thành công
        """
        if not self._enabled:
            return False

        # Parse severity
        try:
            sev = Severity(severity.lower())
        except ValueError:
            sev = Severity.MEDIUM

        notification = Notification(
            title=title,
            message=message,
            severity=sev,
            **kwargs
        )

        # Add to history
        self._history.append(notification)
        if len(self._history) > 100:
            self._history = self._history[-100:]

        # Callback
        if self._callback:
            try:
                self._callback(notification)
            except Exception:
                pass

        # Send notification
        return self._send_notification(notification, duration)

    def _send_notification(self, notification: Notification, duration: float) -> bool:
        """Gửi notification qua available method."""
        title = notification.title
        message = notification.message

        # Method 1: win10toast
        if self._toaster and isinstance(self._toaster, ToastNotifier):
            try:
                # win10toast doesn't support custom duration well on all systems
                self._toaster.show_toast(
                    title=title,
                    msg=message,
                    duration=int(duration),
                    threaded=False
                )
                return True
            except Exception:
                pass

        # Method 2: plyer
        elif self._toaster == "plyer":
            try:
                notification.notify(
                    title=title,
                    message=message,
                    app_name="Ransomware Detector",
                    timeout=duration
                )
                return True
            except Exception:
                pass

        # Method 3: Windows ctypes (fallback)
        if platform.system() == "Windows":
            return self._windows_toast_fallback(title, message)

        # Method 4: Console print (fallback)
        self._console_print(notification)
        return False

    def _windows_toast_fallback(self, title: str, message: str) -> bool:
        """Fallback using Windows PowerShell."""
        try:
            import subprocess
            # Use PowerShell to show toast
            ps_script = f'''
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
            
            $template = @"
            <toast>
                <visual>
                    <binding template="ToastText02">
                        <text id="1">{title}</text>
                        <text id="2">{message}</text>
                    </binding>
                </visual>
                <audio src="ms-winsoundevent:Notification.Default"/>
            </toast>
"@
            
            $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
            $xml.LoadXml($template)
            
            $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Ransomware Detector").Show($toast)
            '''
            # Silently run - might fail without admin
            subprocess.Popen(
                ["powershell", "-WindowStyle", "Hidden", "-Command", ps_script],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return True
        except Exception:
            pass

        return False

    def _console_print(self, notification: Notification):
        """Fallback: print to console with colors."""
        # ANSI color codes
        colors = {
            Severity.LOW: "\033[94m",      # Blue
            Severity.MEDIUM: "\033[93m",   # Yellow
            Severity.HIGH: "\033[91m",      # Red
            Severity.CRITICAL: "\033[91m\033[1m",  # Bold Red
        }
        reset = "\033[0m"

        color = colors.get(notification.severity, "")
        print(f"{color}[{notification.severity.value.upper()}] {notification.title}: {notification.message}{reset}")

    def notify_ransomware_alert(
        self,
        alert_type: str,
        process_name: str,
        file_count: int,
        details: str = ""
    ) -> bool:
        """
        Gửi alert đặc biệt cho ransomware detection.

        Args:
            alert_type: Loại alert (encryption_burst, extension_change, etc)
            process_name: Tên process gây ra
            file_count: Số file bị ảnh hưởng
            details: Thông tin thêm

        Returns:
            True nếu gửi thành công
        """
        titles = {
            "encryption_burst": "Mass Encryption Detected!",
            "extension_change": "Suspicious File Rename!",
            "rapid_ops": "Rapid File Operations!",
            "suspicious_process": "Suspicious Process Detected!",
        }

        messages = {
            "encryption_burst": f"{file_count} files encrypted by {process_name}",
            "extension_change": f"Files renamed to suspicious extension by {process_name}",
            "rapid_ops": f"{file_count} files/second by {process_name}",
            "suspicious_process": f"Suspicious activity from {process_name}",
        }

        title = titles.get(alert_type, "Ransomware Alert")
        message = messages.get(alert_type, details)
        severity = "critical" if alert_type in ("encryption_burst", "extension_change") else "high"

        if details:
            message += f"\n{details}"

        return self.notify(title, message, severity)

    def clear_history(self):
        """Xóa notification history."""
        self._history.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Lấy notification statistics."""
        return {
            "total": len(self._history),
            "by_severity": self._count_by_severity(),
            "enabled": self._enabled,
            "sound_enabled": self._sound_enabled,
            "available": self.is_available,
        }

    def _count_by_severity(self) -> Dict[str, int]:
        """Đếm notifications theo severity."""
        counts = {s.value: 0 for s in Severity}
        for n in self._history:
            counts[n.severity.value] += 1
        return counts


# Singleton instance
_notifier: Optional[NotificationManager] = None


def get_notifier() -> NotificationManager:
    """Lấy singleton NotificationManager instance."""
    global _notifier
    if _notifier is None:
        _notifier = NotificationManager()
    return _notifier
