"""
tray_manager.py
================
Task 4: System Tray Integration (v2.3).

Provides system tray icon and context menu for the application.
Features:
  - Programmatic shield icon generation using Pillow
  - Dynamic context menu with alert count
  - Minimize to tray on window close
  - Flash red icon on CRITICAL threat
  - Protection toggle

Requirements:
  - pystray>=0.19.5
  - Pillow>=10.0.0
"""

import logging
import threading
import time
from typing import Callable, Optional

try:
    from PIL import Image, ImageDraw

    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    logging.warning("Pillow not available - tray icon will use default")

try:
    import pystray

    PYSTRRAY_AVAILABLE = True
except ImportError:
    PYSTRRAY_AVAILABLE = False
    pystray = None  # type: ignore
    logging.warning("pystray not available - system tray will be disabled")

logger = logging.getLogger(__name__)

# Stub types for when pystray is not available
if not PYSTRRAY_AVAILABLE:
    class MenuStub:
        Item = None
        SEPARATOR = None

    class IconStub:
        pass

    pystray = type("pystray", (), {"Menu": MenuStub, "Icon": IconStub})()  # type: ignore


class TrayManager:
    """
    System Tray Manager for Ransomware Detector.
    Manages tray icon, menu, and notification behavior.
    """

    STATUS_COLORS = {
        "safe": (0, 200, 0),  # green
        "warning": (255, 180, 0),  # yellow
        "threat": (220, 0, 0),  # red
        "off": (100, 100, 100),  # gray
    }

    def __init__(self, app_window=None):
        """
        Initialize TrayManager.

        Args:
            app_window: Reference to main GUI window (optional)
        """
        self._app_window = app_window
        self._icon: Optional[pystray.Icon] = None
        self._protection_enabled = True
        self._alert_count = 0
        self._current_status = "safe"
        self._on_open_callback: Optional[Callable] = None
        self._on_quit_callback: Optional[Callable] = None
        self._on_toggle_protection: Optional[Callable] = None
        self._on_view_alerts: Optional[Callable] = None
        self._on_quick_scan: Optional[Callable] = None

    def create_icon(self, status: str = "safe") -> Image.Image:
        """
        Generate 64x64 shield icon programmatically using Pillow.

        Args:
            status: One of "safe", "warning", "threat", "off"

        Returns:
            PIL Image object
        """
        if not PILLOW_AVAILABLE:
            return Image.new("RGBA", (64, 64), (0, 0, 0, 0))

        color = self.STATUS_COLORS.get(status, self.STATUS_COLORS["safe"])
        size = 64
        image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)

        margin = 8
        top = margin
        bottom = size - margin
        left = margin
        right = size - margin

        shield_points = [
            (size // 2, top),
            (right, top + 10),
            (right, bottom - 15),
            (size // 2, bottom),
            (left, bottom - 15),
            (left, top + 10),
        ]

        draw.polygon(shield_points, fill=color)
        draw.polygon(shield_points, outline=(50, 50, 50), width=2)

        if status == "safe":
            check_points = [
                (20, 35),
                (28, 45),
                (44, 25),
            ]
            draw.line(check_points, fill=(255, 255, 255), width=4)
        elif status == "threat":
            draw.line([(22, 22), (42, 42)], fill=(255, 255, 255), width=4)
            draw.line([(42, 22), (22, 42)], fill=(255, 255, 255), width=4)

        return image

    def build_menu(self, alert_count: int = 0) -> pystray.Menu:
        """
        Build context menu with dynamic alert count.

        Args:
            alert_count: Number of active alerts to display

        Returns:
            pystray.Menu object
        """
        protection_text = "Bảo vệ: BẬT" if self._protection_enabled else "Bảo vệ: TẮT"

        menu_items = [
            pystray.MenuItem("Mở tổng quan", self._on_open),
            pystray.MenuItem(protection_text, self._on_toggle_protection),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quét nhanh...", self._on_quick_scan_action),
            pystray.MenuItem(f"Xem cảnh báo ({alert_count})", self._on_view_alerts),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Cài đặt", self._on_settings),
            pystray.MenuItem("Giới thiệu v2.3", self._on_about),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Thoát", self._on_quit),
        ]

        return pystray.Menu(*menu_items)

    def _on_open(self, icon=None, item=None):
        """Open main window."""
        if self._on_open_callback:
            self._on_open_callback()
        elif self._app_window:
            try:
                self._app_window.deiconify()
                self._app_window.lift()
                self._app_window.focus()
            except Exception:
                pass

    def _on_toggle_protection(self, icon=None, item=None):
        """Toggle protection on/off."""
        self._protection_enabled = not self._protection_enabled
        if self._on_toggle_protection:
            self._on_toggle_protection(self._protection_enabled)
        self._update_menu()

    def _on_quick_scan_action(self, icon=None, item=None):
        """Open the app and trigger the quick scan flow."""
        if self._on_quick_scan:
            self._on_quick_scan()
        if self._app_window:
            try:
                self._app_window.deiconify()
                self._app_window.lift()
            except Exception:
                pass

    def _on_view_alerts(self, icon=None, item=None):
        """View alerts."""
        if self._on_view_alerts:
            self._on_view_alerts()
        if self._app_window:
            try:
                self._app_window.deiconify()
                self._app_window.lift()
            except Exception:
                pass

    def _on_settings(self, icon=None, item=None):
        """Open settings."""
        if self._app_window:
            try:
                self._app_window.deiconify()
                self._app_window.lift()
            except Exception:
                pass

    def _on_about(self, icon=None, item=None):
        """Show about dialog."""
        logger.info("About: Ransomware Entropy Detector v2.3")

    def _on_quit(self, icon=None, item=None):
        """Quit application."""
        if self._on_quit_callback:
            self._on_quit_callback()
        self.stop()

    def _update_menu(self):
        """Update tray menu."""
        if self._icon:
            self._icon.menu = self.build_menu(self._alert_count)

    def run(self):
        """Start the system tray icon."""
        if not PYSTRRAY_AVAILABLE:
            logger.warning("pystray not available - tray disabled")
            return

        if self._icon:
            logger.warning("Tray icon already running")
            return

        try:
            self._icon = pystray.Icon(
                "ransomware_detector",
                self.create_icon(self._current_status),
                "Ransomware Detector v2.3",
                menu=self.build_menu(self._alert_count),
            )

            self._tray_thread = threading.Thread(target=self._icon.run, daemon=True)
            self._tray_thread.start()
            logger.info("System tray icon started")
        except Exception as e:
            logger.error(f"Failed to start tray icon: {e}")

    def stop(self):
        """Stop the system tray icon."""
        if self._icon:
            try:
                self._icon.stop()
                self._icon = None
                logger.info("System tray icon stopped")
            except Exception as e:
                logger.error(f"Error stopping tray icon: {e}")

    def set_status(self, status: str):
        """
        Update tray icon status.

        Args:
            status: One of "safe", "warning", "threat", "off"
        """
        self._current_status = status
        if self._icon:
            try:
                self._icon.icon = self.create_icon(status)
                logger.info(f"Tray status changed to: {status}")
            except Exception as e:
                logger.error(f"Error updating tray icon: {e}")

    def update_alert_count(self, count: int):
        """Update the alert count badge."""
        self._alert_count = count
        self._update_menu()

    def increment_alerts(self):
        """Increment alert count."""
        self._alert_count += 1
        self._update_menu()

    def flash_icon(self, times: int = 3):
        """
        Flash red icon N times on CRITICAL threat.

        Args:
            times: Number of flashes
        """
        if not self._icon or not PILLOW_AVAILABLE:
            return

        def _flash():
            for _ in range(times):
                self._icon.icon = self.create_icon("threat")
                time.sleep(0.5)
                self._icon.icon = self.create_icon(self._current_status)
                time.sleep(0.5)

        thread = threading.Thread(target=_flash, daemon=True)
        thread.start()

    def set_callbacks(
        self,
        on_open: Callable = None,
        on_quit: Callable = None,
        on_toggle_protection: Callable = None,
        on_view_alerts: Callable = None,
        on_quick_scan: Callable = None,
    ):
        """Set callback functions for menu actions."""
        self._on_open_callback = on_open
        self._on_quit_callback = on_quit
        self._on_toggle_protection = on_toggle_protection
        self._on_view_alerts = on_view_alerts
        self._on_quick_scan = on_quick_scan

    def minimize_to_tray(self):
        """Hide the app window to tray."""
        if self._app_window:
            try:
                self._app_window.withdraw()
            except Exception:
                pass

    def restore_from_tray(self):
        """Restore the app window from tray."""
        if self._app_window:
            try:
                self._app_window.deiconify()
                self._app_window.lift()
                self._app_window.focus()
            except Exception:
                pass


_tray_manager: Optional[TrayManager] = None


def get_tray_manager(app_window=None) -> TrayManager:
    """Get singleton TrayManager instance."""
    global _tray_manager
    if _tray_manager is None:
        _tray_manager = TrayManager(app_window)
    return _tray_manager
