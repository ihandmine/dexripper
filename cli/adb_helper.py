"""
DexRipper - ADB Helper

Wraps ADB commands for device interaction.
"""

import subprocess
import re
from typing import Optional


class AdbHelper:
    """ADB command wrapper."""

    def __init__(self, serial: Optional[str] = None):
        self.serial = serial
        self._adb = ["adb"]
        if serial:
            self._adb = ["adb", "-s", serial]

    def _run(self, args: list, timeout: int = 30) -> str:
        """Run an ADB command and return stdout."""
        cmd = self._adb + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except FileNotFoundError:
            return ""

    def check_device(self) -> bool:
        """Check if an ADB device is connected."""
        out = self._run(["devices"])
        lines = out.split("\n")
        for line in lines[1:]:
            if "\tdevice" in line:
                return True
        return False

    def shell(self, cmd: str, timeout: int = 30) -> str:
        """Run a shell command on device."""
        return self._run(["shell", cmd], timeout=timeout)

    def get_pid(self, package: str) -> Optional[int]:
        """Get PID of a running package."""
        out = self.shell(f"pidof {package}")
        if out and out.isdigit():
            return int(out)
        return None

    def push(self, local: str, remote: str) -> bool:
        """Push a file to device."""
        out = self._run(["push", local, remote])
        return "pushed" in out.lower() or "file" in out.lower()

    def pull(self, remote: str, local: str) -> bool:
        """Pull a file/directory from device."""
        out = self._run(["pull", remote, local], timeout=120)
        return "pulled" in out.lower() or "file" in out.lower() or "files" in out.lower()

    def install(self, apk_path: str) -> str:
        """Install an APK."""
        return self._run(["install", "-r", apk_path], timeout=60)

    def force_stop(self, package: str) -> str:
        """Force stop a package."""
        return self.shell(f"am force-stop {package}")

    def start_app(self, package: str) -> str:
        """Start an app via monkey."""
        return self.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1")

    def get_device_info(self) -> dict:
        """Get device information."""
        info = {}
        info["model"] = self.shell("getprop ro.product.model")
        info["android"] = self.shell("getprop ro.build.version.release")
        info["sdk"] = self.shell("getprop ro.build.version.sdk")
        info["abi"] = self.shell("getprop ro.product.cpu.abi")
        info["kernel"] = self.shell("uname -r")
        return info
