#!/usr/bin/env python3
# Test copy of usb_test_v1.py
"""
Hex Protocol Monitor for Medical Devices - v7 Kali Linux Hardened
Specialized for devices using hex-based serial protocols, such as blood glucose meters.
Enhanced Edition v7: Hardened for Kali Linux with improved permission handling for serial and USB monitoring, and clearer user guidance.
"""
import sys
import time
import threading
import subprocess
import serial
import os
import random
import json
import csv
from datetime import datetime
from pathlib import Path
from serial.tools import list_ports
try:
    import usb.core
    import usb.util
except Exception:
    usb = None


def _vid_pid_from_port_name(port: str):
    try:
        if not port:
            return None, None
        for p in list_ports.comports():
            if p.device == port:
                return getattr(p, "vid", None), getattr(p, "pid", None)
    except Exception:
        pass
    return None, None


def _safe_len(x):
    try:
        return len(x)
    except Exception:
        return None

USB_REQ_GET_STATUS = 0x00
USB_REQ_GET_DESCRIPTOR = 0x06
USB_DT_DEVICE = 0x01
BMRT_DEV_STD_IN = 0x80  # IN | Standard | Device

# Terminal color support
try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
    _COLORAMA_AVAILABLE = True
    _COLOR_MAP = {
        "INFO": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "SUCCESS": Fore.CYAN,
    }
except Exception:
    _COLORAMA_AVAILABLE = False
    _COLOR_MAP = {}

import builtins as _builtins

# Boofuzz support for protocol-aware fuzzing
try:
    from boofuzz import (
        Session,
        Target,
        s_initialize,
        s_static,
        s_block_start,
        s_block_end,
        s_size,
        s_byte,
        s_string,
        s_checksum,
        s_get,
    )
    from boofuzz.connections import SerialConnection

    _BOOFUZZ_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    _BOOFUZZ_AVAILABLE = False
    _builtins.print(
        "[!] boofuzz not installed. Install with 'pip install -r requirements.txt' to enable protocol fuzzing."
    )

_original_print = _builtins.print


if not _COLORAMA_AVAILABLE:
    _original_print(
        "[!] colorama not installed. Install with 'pip install colorama' for colored logs."
    )


def _color_text(level, text):
    color = _COLOR_MAP.get(level)
    if color:
        return f"{color}{text}{Style.RESET_ALL}"
    return text


def print(*args, level=None, **kwargs):  # type: ignore
    """Wrapper around built-in print providing optional color support."""
    if _COLORAMA_AVAILABLE:
        if level and args:
            args = tuple(_color_text(level, str(a)) if isinstance(a, str) else a for a in args)
        elif args and isinstance(args[0], str):
            prefix = args[0][:3]
            level = {
                "[*]": "INFO",
                "[!]": "WARNING",
                "[-]": "ERROR",
                "[+]": "SUCCESS",
            }.get(prefix)
            if level:
                first = _color_text(level, args[0])
                args = (first, *args[1:])
    return _original_print(*args, **kwargs)




def check_usb_link_and_endpoints(
    vid=None,
    pid=None,
    port=None,
    timeout_ms=None,
    strict=None,
    logger=None,
) -> bool:
    if timeout_ms is None:
        timeout_ms = int(os.getenv("USB_EP0_TIMEOUT_MS", "1000"))
    if strict is None:
        strict = os.getenv("STRICT_EP0", "0") == "1"  # 預設寬鬆

    # 解析 VID/PID：參數 → port 反查 → env
    if vid is None or pid is None:
        v_from_port, p_from_port = _vid_pid_from_port_name(port) if port else (None, None)
        vid = vid if vid is not None else v_from_port
        pid = pid if pid is not None else p_from_port
    if vid is None or pid is None:
        v = os.getenv("USB_VID"); p = os.getenv("USB_PID")
        if v and p:
            try:
                vid = int(v, 16); pid = int(p, 16)
            except Exception:
                pass

    # PyUSB 不可用 → 跳過
    if "usb" not in globals() or usb is None:
        if logger:
            try: logger.log_info("EP0_CHECK", "PyUSB not available - skipping EP0")
            except: pass
        return True

    # 仍無 VID/PID → 跳過，不判 FAIL
    if vid is None or pid is None:
        if logger:
            try: logger.log_info("EP0_CHECK", f"skip: no VID/PID (port={port})")
            except: pass
        return True

    dev = usb.core.find(idVendor=vid, idProduct=pid)
    if dev is None:
        if logger:
            try: logger.log_info("EP0_CHECK", f"device not found by VID/PID (0x{vid:04X}:0x{pid:04X})")
            except: pass
        return False if strict else True

    # 僅在沒有 active configuration 時設定
    try:
        _ = dev.get_active_configuration()
    except Exception:
        try:
            dev.set_configuration()
        except Exception:
            pass

    if logger:
        try: logger.log_info("EP0_CHECK", f"Using VID=0x{vid:04X}, PID=0x{pid:04X}, port={port}")
        except: pass

    # 帶重試的 ctrl_transfer（PIPE/STALL 視為中立 -> 回 None）
    def _ctrl_xfer(bmrt, breq, wval, wind, length):
        retries = int(os.getenv("EP0_RETRY", "1"))
        delay = int(os.getenv("EP0_RETRY_DELAY_MS", "100")) / 1000.0
        last_exc = None
        for i in range(retries + 1):
            try:
                return dev.ctrl_transfer(bmrt, breq, wval, wind, length, timeout=timeout_ms)
            except usb.core.USBError as e:
                last_exc = e
                if getattr(e, "errno", None) in (32,):  # EPIPE=32
                    return None
                if i < retries:
                    time.sleep(delay)
            except Exception as e:
                last_exc = e
                if i < retries:
                    time.sleep(delay)
        return None

    # ① Device Descriptor 主判
    desc = _ctrl_xfer(0x80, 0x06, (0x01 << 8) | 0x00, 0, 18)
    n_desc = _safe_len(desc)
    device_layer_ok = bool(n_desc is not None and n_desc >= 18)
    if logger:
        try: logger.log_info("EP0_CHECK", f"GET_DESCRIPTOR len={n_desc if n_desc is not None else 'fail'}")
        except: pass

    # ② Device Status 輔助（成功也算通）
    st_dev = _ctrl_xfer(0x80, 0x00, 0, 0, 2)
    n_st = _safe_len(st_dev)
    if n_st == 2:
        device_layer_ok = True
    if logger:
        try: logger.log_info("EP0_CHECK", f"GET_STATUS(dev) len={n_st if n_st is not None else 'fail'}")
        except: pass

    # ③ Endpoints：Bulk/Interrupt HALT 位（bit0==0 健康）
    endpoints_ok = True  # 沒端點時保持 True（中立）
    try:
        cfg = dev.get_active_configuration()
        ep_addrs = []
        for intf in cfg:
            for ep in intf:
                typ = usb.util.endpoint_type(ep.bmAttributes)
                if typ in (usb.util.ENDPOINT_TYPE_BULK, usb.util.ENDPOINT_TYPE_INTR):
                    ep_addrs.append(ep.bEndpointAddress)
        if ep_addrs:
            for addr in ep_addrs:
                st = _ctrl_xfer(0x82, 0x00, 0, addr, 2)
                n = _safe_len(st)
                ok = bool(n == 2 and (st[0] & 0x01) == 0) if n == 2 else False
                if not ok:
                    endpoints_ok = False
                    if logger:
                        try: logger.log_info("EP0_CHECK", f"EP 0x{addr:02X} BAD: {bytes(st) if n else None}")
                        except: pass
                    break
            if endpoints_ok and logger:
                try: logger.log_info("EP0_CHECK", "Endpoints healthy: " + ", ".join(f"0x{a:02X}" for a in ep_addrs))
                except: pass
    except Exception as e:
        if strict:
            endpoints_ok = False
        if logger:
            try: logger.log_info("EP0_CHECK", f"endpoint check exception: {e}")
            except: pass

    # 決策
    if device_layer_ok or endpoints_ok:
        return True
    return False if strict else True


def build_fuzz_session(port, baudrate, pre_send_callbacks=None, post_test_case_callbacks=None, restart_callbacks=None):
    """Build a boofuzz session for [STX][LEN][CMD][PAYLOAD][CHECKSUM][ETX] protocol."""
    if not _BOOFUZZ_AVAILABLE:
        return None, None

    def _calc_checksum(data: bytes) -> bytes:
        if _builtins.len(data) < 2:
            return b"\x00"
        cmd = data[1]
        payload = data[2:]
        length_field = _builtins.len(payload)
        checksum = (length_field ^ cmd ^ sum(payload)) & 0xFF
        return bytes([checksum])

    target = Target(connection=SerialConnection(port=port, baudrate=baudrate))
    session = Session(target=target, keep_web_open=False, pre_send_callbacks=pre_send_callbacks, post_test_case_callbacks=post_test_case_callbacks, restart_callbacks=restart_callbacks)

    s_initialize("usb_packet")
    s_static(b"\x02", name="stx")
    s_block_start("body")
    s_size("payload", length=1, name="length_field", fuzzable=False)
    s_byte(name="cmd")
    s_block_start("payload")
    s_string("A", name="payload_data", max_len=256)
    s_block_end("payload")
    s_block_end("body")
    s_checksum("body", _calc_checksum, length=1, fuzzable=False, name="checksum")
    s_static(b"\x03", name="etx")

    session.connect(s_get("usb_packet"))
    return session, target


class SessionLogger:
    def __init__(self, session_name=None):
        # Create logs directory
        self.logs_dir = Path("hex_monitor_logs")
        self.logs_dir.mkdir(exist_ok=True)

        # Generate session name
        if not session_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            session_name = f"session_{timestamp}"

        self.session_name = session_name
        self.session_dir = self.logs_dir / session_name
        self.session_dir.mkdir(exist_ok=True)

        # Initialize log files
        self.main_log_file = self.session_dir / "main.log"
        self.commands_log_file = self.session_dir / "commands.json"
        self.usb_log_file = self.session_dir / "usb_data.csv"
        self.analysis_log_file = self.session_dir / "analysis_report.txt"

        # Initialize data structures
        self.session_data = {
            "session_name": session_name,
            "start_time": datetime.now().isoformat(),
            "device_info": {},
            "test_parameters": {},
            "commands": [],
            "usb_data": [],
            "statistics": {},
            "analysis_results": {},
        }

        # Initialize main log
        self.log_info("SESSION_START", f"Session initialized: {session_name}")
        self.log_info("SETUP", f"Log directory: {self.session_dir}")

    def log_info(self, category, message, data=None):
        """Log information message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] [{category:12s}] {message}"

        # Write to main log file
        with open(self.main_log_file, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")

        # Determine log level for colored output
        level = "INFO"
        cat_upper = category.upper()
        if "ERROR" in cat_upper:
            level = "ERROR"
        elif "WARN" in cat_upper:
            level = "WARNING"
        elif "SUCCESS" in cat_upper:
            level = "SUCCESS"

        # Print to console with color if available
        print(log_entry, level=level)

        # Store additional data if provided
        if data:
            self.session_data.setdefault("detailed_logs", []).append(
                {"timestamp": timestamp, "category": category, "message": message, "data": data}
            )

    def log_command(self, command_data):
        """Log command execution details."""
        timestamp = datetime.now().isoformat()
        command_entry = {
            "timestamp": timestamp,
            "command": command_data.get("command", ""),
            "description": command_data.get("description", ""),
            "response": command_data.get("response", None),
            "success": command_data.get("response") is not None,
            "baudrate": command_data.get("baudrate", None),
            "test_phase": command_data.get("test_phase", "manual"),
            "response_time_ms": command_data.get("response_time_ms", None),
            "raw_response_bytes": command_data.get("raw_response_bytes", None),
        }

        self.session_data["commands"].append(command_entry)

        # Log to main file
        status = "SUCCESS" if command_entry["success"] else "NO_RESPONSE"
        self.log_info(
            "COMMAND",
            f"{status}: {command_data.get('command', '')} ({command_data.get('description', '')})",
        )

        # Update commands JSON file
        with open(self.commands_log_file, "w", encoding="utf-8") as f:
            json.dump(self.session_data["commands"], f, indent=2)

    def log_usb_data(self, timestamp, line):
        """Log USB monitoring data."""
        usb_entry = {
            "timestamp": timestamp,
            "raw_line": line,
            "parsed_data": self._parse_usb_line(line),
        }

        self.session_data["usb_data"].append(usb_entry)

        # Write to CSV
        file_exists = self.usb_log_file.exists()
        with open(self.usb_log_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["timestamp", "direction", "data", "ascii", "raw_line"])

            parsed = usb_entry["parsed_data"]
            writer.writerow(
                [
                    timestamp,
                    parsed.get("direction", ""),
                    parsed.get("hex_data", ""),
                    parsed.get("ascii_data", ""),
                    line,
                ]
            )

    def _parse_usb_line(self, line):
        """Parse USB monitor line to extract relevant information."""
        parsed = {"direction": "", "hex_data": "", "ascii_data": ""}

        try:
            if "Bo:" in line:  # Bulk Out
                parsed["direction"] = "OUT"
            elif "Bi:" in line:  # Bulk In
                parsed["direction"] = "IN"

            if "=" in line:
                hex_data = line.split("=")[-1].strip()
                parsed["hex_data"] = hex_data
                parsed["ascii_data"] = self._hex_to_ascii_safe(hex_data)
        except Exception:
            pass

        return parsed

    def _hex_to_ascii_safe(self, hex_string):
        """Safely converts a hex string to a printable ASCII string."""
        try:
            hex_clean = hex_string.replace(" ", "")
            if len(hex_clean) % 2 != 0:
                return "Invalid format"
            bytes_data = bytes.fromhex(hex_clean)
            return "".join(chr(b) if 32 <= b <= 126 else "." for b in bytes_data)
        except Exception:
            return "Conversion failed"

    def set_device_info(self, info):
        """Set device information."""
        self.session_data["device_info"] = info
        log_message = f"Device TTY: {info.get('tty_device')}"
        if info.get("bus") and info.get("device"):
            log_message += f", Bus: {info.get('bus')}, Device: {info.get('device')}"
        self.log_info("DEVICE_INFO", log_message)

    def set_test_parameters(self, params):
        """Set test parameters."""
        self.session_data["test_parameters"] = params
        self.log_info(
            "TEST_PARAMS",
            f"Mode: {params.get('mode')}, Baudrate: {params.get('baudrate')}, Max Tests: {params.get('max_tests')}",
        )

    def update_statistics(self, stats):
        """Update session statistics."""
        self.session_data["statistics"].update(stats)

    def generate_analysis_report(self):
        """Generate comprehensive analysis report."""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("HEX PROTOCOL MONITOR - ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Session: {self.session_name}")
        report_lines.append(f"Start Time: {self.session_data['start_time']}")
        report_lines.append(f"End Time: {datetime.now().isoformat()}")
        report_lines.append("")

        # Device Information
        device_info = self.session_data.get("device_info", {})
        if device_info:
            report_lines.append("DEVICE INFORMATION:")
            report_lines.append(f"  TTY: {device_info.get('tty_device', 'Unknown')}")
            if device_info.get("bus") and device_info.get("device"):
                report_lines.append(f"  Bus: {device_info.get('bus')}")
                report_lines.append(f"  Device: {device_info.get('device')}")
            report_lines.append("")

        # Test Parameters
        test_params = self.session_data.get("test_parameters", {})
        if test_params:
            report_lines.append("TEST PARAMETERS:")
            for key, value in test_params.items():
                report_lines.append(f"  {key}: {value}")
            report_lines.append("")

        # Command Statistics
        commands = self.session_data.get("commands", [])
        if commands:
            successful_commands = [cmd for cmd in commands if cmd["success"]]

            report_lines.append("COMMAND STATISTICS:")
            report_lines.append(f"  Total Commands Sent: {len(commands)}")
            report_lines.append(f"  Successful Responses: {len(successful_commands)}")
            if commands:
                success_rate = len(successful_commands) / len(commands) * 100
                report_lines.append(f"  Success Rate: {success_rate:.2f}%")

            # Group by test phase
            phase_stats = {}
            for cmd in commands:
                phase = cmd.get("test_phase", "unknown")
                phase_stats[phase] = phase_stats.get(phase, 0) + 1

            if phase_stats:
                report_lines.append("  Commands by Phase:")
                for phase, count in phase_stats.items():
                    successful_in_phase = len(
                        [
                            cmd
                            for cmd in commands
                            if cmd.get("test_phase") == phase and cmd["success"]
                        ]
                    )
                    report_lines.append(
                        f"    {phase}: {count} total, {successful_in_phase} successful"
                    )
            report_lines.append("")

        # Response Analysis
        if commands:
            successful_commands = [cmd for cmd in commands if cmd["success"]]
            if successful_commands:
                report_lines.append("RESPONSE ANALYSIS:")

                # Group by response pattern
                response_groups = {}
                for cmd in successful_commands:
                    response = cmd.get("response", "")
                    if "HEX:" in response:
                        hex_part = response.split("HEX:")[1].split("|")[0].strip()
                        response_groups.setdefault(hex_part, []).append(cmd)

                report_lines.append(f"  Unique Response Patterns: {len(response_groups)}")
                for i, (pattern, cmds) in enumerate(response_groups.items(), 1):
                    report_lines.append(f"    Pattern {i}: {pattern}")
                    report_lines.append(f"      Triggered by {len(cmds)} commands")
                    if len(cmds) <= 3:
                        for cmd in cmds:
                            report_lines.append(
                                f"        - {cmd['command']} ({cmd['description']})"
                            )
                    else:
                        for cmd in cmds[:2]:
                            report_lines.append(
                                f"        - {cmd['command']} ({cmd['description']})"
                            )
                        report_lines.append(f"        ... and {len(cmds) - 2} more")
                report_lines.append("")

        # USB Data Summary
        usb_data = self.session_data.get("usb_data", [])
        if usb_data:
            in_packets = [
                entry for entry in usb_data if entry.get("parsed_data", {}).get("direction") == "IN"
            ]
            out_packets = [
                entry
                for entry in usb_data
                if entry.get("parsed_data", {}).get("direction") == "OUT"
            ]

            report_lines.append("USB DATA SUMMARY:")
            report_lines.append(f"  Total USB Packets Captured: {len(usb_data)}")
            report_lines.append(f"  Outgoing Packets (Host->Device): {len(out_packets)}")
            report_lines.append(f"  Incoming Packets (Device->Host): {len(in_packets)}")
            report_lines.append("")

        # Recommendations
        report_lines.append("RECOMMENDATIONS:")
        if commands:
            successful_commands = [cmd for cmd in commands if cmd["success"]]
            if successful_commands:
                report_lines.append("  ✓ Device is responsive - communication established")

                # Analyze successful command patterns
                successful_patterns = set()
                for cmd in successful_commands:
                    cmd_bytes = cmd["command"].replace(" ", "")
                    if len(cmd_bytes) >= 2:
                        successful_patterns.add(cmd_bytes[:2])  # First byte

                if successful_patterns:
                    report_lines.append(
                        f"  ✓ Successful command prefixes: {', '.join(sorted(successful_patterns))}"
                    )

                # Check for common medical device patterns
                medical_indicators = []
                for cmd in successful_commands:
                    if "02" in cmd["command"] and "03" in cmd["command"]:
                        medical_indicators.append("STX/ETX framing detected")
                    elif "7E" in cmd["command"]:
                        medical_indicators.append("Frame delimiter (0x7E) detected")

                for indicator in set(medical_indicators):
                    report_lines.append(f"  ✓ {indicator}")

            else:
                report_lines.append(
                    "  ! No successful responses - try different baudrates or protocols"
                )

        report_lines.append("  → Review successful commands for protocol reverse engineering")
        report_lines.append("  → Analyze USB capture data for timing and framing information")
        report_lines.append("  → Use interactive mode for manual protocol exploration")
        report_lines.append("")

        # File Locations
        report_lines.append("GENERATED FILES:")
        report_lines.append(f"  Main Log: {self.main_log_file}")
        report_lines.append(f"  Commands JSON: {self.commands_log_file}")
        report_lines.append(f"  USB Data CSV: {self.usb_log_file}")
        report_lines.append(f"  This Report: {self.analysis_log_file}")
        report_lines.append("")

        report_content = "\n".join(report_lines)

        # Write report to file
        with open(self.analysis_log_file, "w", encoding="utf-8") as f:
            f.write(report_content)

        # Also save session data as JSON
        session_json_file = self.session_dir / "session_data.json"
        with open(session_json_file, "w", encoding="utf-8") as f:
            json.dump(self.session_data, f, indent=2)

        return report_content

    def finalize_session(self):
        """Finalize the session and generate final report."""
        self.session_data["end_time"] = datetime.now().isoformat()
        self.log_info("SESSION_END", "Session completed")

        # Generate and display analysis report
        report = self.generate_analysis_report()
        print("\n" + report)

        print(f"\n[+] Session '{self.session_name}' completed.")
        print(f"[+] All logs saved to: {self.session_dir}")


class HexProtocolMonitor:
    def __init__(self, tty_device, logger=None):
        self.tty_device = tty_device
        self.monitoring = False
        self.usb_data = []
        self.serial_port = None
        self.successful_commands = []
        self.logger = logger
        self.is_linux = sys.platform.startswith("linux")
        self.bus = None
        self.device = None

        if self.logger:
            self.logger.set_device_info({"tty_device": tty_device})

    def setup_serial(self, baudrate=9600):
        """Sets up the serial port connection."""
        try:
            if self.serial_port:
                self.serial_port.close()

            self.serial_port = serial.Serial(
                port=self.tty_device,
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1,
            )

            message = f"Serial port configured: {self.tty_device} at {baudrate} baud, 8N1"
            print(f"[+] {message}")
            if self.logger:
                self.logger.log_info("SERIAL_SETUP", message, {"baudrate": baudrate})
            return True
        except serial.SerialException as e:
            error_msg = f"Serial port setup failed: {e}"
            print(f"[-] {error_msg}")
            if self.is_linux and "Permission denied" in str(e):
                print("[!] PERMISSION ERROR: You may not have access to the serial port.")
                print("    Try adding your user to the 'dialout' group:")
                print("    sudo usermod -a -G dialout $USER")
                print("    Then, log out and log back in for the change to take effect.")
            if self.logger:
                self.logger.log_info(
                    "SERIAL_ERROR", error_msg, {"baudrate": baudrate, "error": str(e)}
                )
            return False
        except Exception as e:
            error_msg = f"An unexpected error occurred during serial setup: {e}"
            print(f"[-] {error_msg}")
            if self.logger:
                self.logger.log_info(
                    "SERIAL_ERROR", error_msg, {"baudrate": baudrate, "error": str(e)}
                )
            return False

    def start_usb_monitoring(self, verbose=False):
        """Starts USB monitoring in a background thread (Linux-only)."""

        def debug(message, category="USB_INFO"):
            if not verbose:
                return
            print(f"[*] {message}")
            if self.logger:
                try:
                    self.logger.log_info(category, message)
                except Exception:
                    pass

        self.usbmon_path = None

        if not self.is_linux:
            debug("USB monitoring is only supported on Linux. Skipping.")
            return

        if os.geteuid() != 0:
            debug("USB monitoring requires root privileges. Skipping.", "USB_PERMISSIONS")
            return

        debug_root = Path("/sys/kernel/debug")
        usbmon_dir = debug_root / "usb" / "usbmon"

        def dir_usable(path: Path) -> bool:
            return path.exists() and path.is_dir() and os.access(path, os.R_OK | os.X_OK)

        if not dir_usable(debug_root):
            debug("/sys/kernel/debug is missing or not accessible; usbmon is not available.", "USBMON_UNAVAILABLE")
            return

        if not dir_usable(usbmon_dir):
            debug(
                "usbmon directory not present under /sys/kernel/debug. The usbmon module may not be loaded (try 'sudo modprobe usbmon').",
                "USBMON_UNAVAILABLE",
            )
            return

        # Try to find bus and device for usbmon from the tty device
        self.bus = None
        self.device = None
        try:
            # Get the device path (e.g., /dev/ttyUSB0 -> /sys/class/tty/ttyUSB0)
            tty_name = os.path.basename(self.tty_device)
            sys_path = f"/sys/class/tty/{tty_name}/device"

            if os.path.exists(sys_path):
                # Read USB bus and device numbers from sysfs
                usb_device_path = os.path.realpath(sys_path)
                # The path typically looks like: /sys/devices/pci.../usb1/1-2/1-2:1.0/ttyUSB0
                # We need to find the USB device (e.g., 1-2)
                path_parts = usb_device_path.split("/")
                for i, part in enumerate(path_parts):
                    if part.startswith("usb"):
                        # Found usb bus, next meaningful part should be the device
                        if i + 1 < len(path_parts):
                            usb_device = path_parts[i + 1]
                            # Extract bus number from 'usbN'
                            self.bus = int(part[3:])
                            # For device number, we'll try to read from busnum/devnum files
                            try:
                                with open(f"{'/'.join(path_parts[: i + 2])}/busnum", "r") as f:
                                    self.bus = int(f.read().strip())
                                with open(f"{'/'.join(path_parts[: i + 2])}/devnum", "r") as f:
                                    self.device = int(f.read().strip())
                                break
                            except Exception:
                                pass

            # Fallback: try lsusb and match by tty device using pyserial
            if not self.bus or not self.device:
                from serial.tools import list_ports

                for port in list_ports.comports():
                    if port.device == self.tty_device:
                        if hasattr(port, "location"):
                            # Parse location string like "1-2:1.0"
                            location = port.location
                            if location:
                                bus_info = location.split("-")[0]
                                self.bus = int(bus_info)
                                # Try to get device number from lsusb
                                try:
                                    result = subprocess.run(
                                        ["lsusb"], capture_output=True, text=True, check=True
                                    )
                                    for line in result.stdout.split("\n"):
                                        if f"Bus {self.bus:03d}" in line:
                                            parts = line.split()
                                            self.device = int(parts[3].rstrip(":"))
                                            break
                                except Exception:
                                    pass
                        break

        except FileNotFoundError:
            debug(
                "'lsusb' command not found. Please install usbutils (`sudo apt install usbutils`) to enable USB monitoring."
            )
            return
        except Exception as e:
            debug(f"Error finding USB device information: {e}. Skipping USB monitoring.", "USB_ERROR")
            return

        if not self.bus or not self.device:
            debug("Could not determine USB bus/device for monitoring. Skipping.")
            return

        self.usbmon_path = usbmon_dir / f"{self.bus}u"
        if not (self.usbmon_path.exists() and os.access(self.usbmon_path, os.R_OK)):
            debug(
                f"usbmon node not found or unreadable at {self.usbmon_path}. The usbmon module may not be loaded or permissions are insufficient (try 'sudo modprobe usbmon').",
                "USBMON_UNAVAILABLE",
            )
            return

        self.monitoring = True
        self.usb_data = []

        def monitor_thread():
            try:
                # We already checked for permissions, so this should be safe.
                with open(self.usbmon_path, "r") as f:
                    while self.monitoring:
                        line = f.readline()
                        if line and f"{self.bus}:{self.device:03d}" in line:
                            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                            self.usb_data.append((timestamp, line.strip()))
                            if self.logger:
                                self.logger.log_usb_data(timestamp, line.strip())
            except PermissionError:
                self.monitoring = False
                debug(
                    f"Permission denied for {self.usbmon_path}. USB monitoring typically requires root.",
                    "USB_ERROR",
                )
            except Exception as e:
                self.monitoring = False
                debug(f"USB monitoring error: {e}", "USB_ERROR")

        self.usb_thread = threading.Thread(target=monitor_thread)
        self.usb_thread.daemon = True
        self.usb_thread.start()

        message = "USB monitoring started"
        print(f"[+] {message}")
        if self.logger:
            self.logger.log_info("USB_START", message)

    def stop_usb_monitoring(self):
        """Stops the USB monitoring thread."""
        if not self.monitoring:
            return

        self.monitoring = False
        if hasattr(self, "usb_thread"):
            self.usb_thread.join(timeout=1)

        message = "USB monitoring stopped"
        print(f"[+] {message}")
        if self.logger:
            self.logger.log_info("USB_STOP", message)

    def send_hex_command(self, hex_string, description="", verbose=True, test_phase="manual"):
        """Sends a hexadecimal command to the serial port."""
        start_time = time.time()

        try:
            # Sanitize hex string
            hex_clean = hex_string.replace(" ", "").replace("0x", "")

            # Convert to bytes
            data = bytes.fromhex(hex_clean)

            if verbose:
                print(f"TX > Sending {description}: {hex_string}")
                print(f"     Raw bytes: {' '.join(f'{b:02X}' for b in data)}")

            if self.serial_port and self.serial_port.is_open:
                self.serial_port.write(data)
                self.serial_port.flush()

                # Attempt to read response
                time.sleep(0.1)
                response = self.read_response()
                response_time = (time.time() - start_time) * 1000  # Convert to milliseconds

                # Log command
                if self.logger:
                    self.logger.log_command(
                        {
                            "command": hex_string,
                            "description": description,
                            "response": response,
                            "baudrate": self.serial_port.baudrate if self.serial_port else None,
                            "test_phase": test_phase,
                            "response_time_ms": response_time,
                            "raw_response_bytes": (
                                response.split("HEX:")[1].split("|")[0].strip()
                                if response and "HEX:" in response
                                else None
                            ),
                        }
                    )

                if response:
                    if verbose:
                        print(f"RX < Response: {response}")
                    # Store successful command
                    self.successful_commands.append(
                        {
                            "command": hex_string,
                            "description": description,
                            "response": response,
                            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                            "response_time_ms": response_time,
                        }
                    )
                    return response
                else:
                    if self.logger:
                        self.logger.log_command(
                            {
                                "command": hex_string,
                                "description": description,
                                "response": None,
                                "baudrate": self.serial_port.baudrate if self.serial_port else None,
                                "test_phase": test_phase,
                                "response_time_ms": response_time,
                            }
                        )
            else:
                if verbose:
                    print("[-] Serial port not open")
                return None

        except ValueError as e:
            if verbose:
                print(f"[-] Invalid hex format: {e}")
            if self.logger:
                self.logger.log_info(
                    "COMMAND_ERROR", f"Invalid hex format: {hex_string}", {"error": str(e)}
                )
            return None
        except Exception as e:
            if verbose:
                print(f"[-] Send failed: {e}")
            if self.logger:
                self.logger.log_info(
                    "COMMAND_ERROR", f"Send failed: {hex_string}", {"error": str(e)}
                )
            return None

    def read_response(self, timeout=2):
        """Reads a response from the serial port."""
        if not self.serial_port or not self.serial_port.is_open:
            return None

        try:
            start_time = time.time()
            data = b""

            while (time.time() - start_time) < timeout:
                if self.serial_port.in_waiting > 0:
                    chunk = self.serial_port.read(self.serial_port.in_waiting)
                    data += chunk
                    time.sleep(0.01)
                elif data:  # If data exists and no new data arrives, stop reading
                    break
                else:
                    time.sleep(0.01)

            if data:
                hex_str = " ".join(f"{b:02X}" for b in data)
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
                return f"HEX: {hex_str} | ASCII: '{ascii_str}'"

        except Exception as e:
            error_msg = f"Failed to read response: {e}"
            print(f"[-] {error_msg}")
            if self.logger:
                self.logger.log_info("READ_ERROR", error_msg, {"error": str(e)})

        return None

    def add_custom_frame_delimiter(self, start_byte, end_byte, description=None):
        """Add custom frame delimiters to the standard set."""
        if not hasattr(self, "_custom_delimiters"):
            self._custom_delimiters = []

        desc = description or f"Custom frame [{start_byte:02X}...{end_byte:02X}]"
        self._custom_delimiters.append((start_byte, end_byte, desc))

        if self.logger:
            self.logger.log_info("CUSTOM_DELIMITER", f"Added custom delimiter: {desc}")

    def add_custom_checksum_algorithm(self, checksum_func, description):
        """Add custom checksum algorithm for Phase 1."""
        if not hasattr(self, "_custom_checksums"):
            self._custom_checksums = []

        self._custom_checksums.append((checksum_func, description))

        if self.logger:
            self.logger.log_info("CUSTOM_CHECKSUM", f"Added custom checksum: {description}")

    def add_custom_protocol_pattern(self, prefix, suffix, pattern_name, max_payload_len=8):
        """Add custom protocol pattern for Phase 3."""
        if not hasattr(self, "_custom_patterns"):
            self._custom_patterns = []

        self._custom_patterns.append((prefix, pattern_name, suffix, max_payload_len))

        if self.logger:
            self.logger.log_info("CUSTOM_PATTERN", f"Added custom pattern: {pattern_name}")

    def demo_custom_extensions(self):
        """
        Demonstration of how to add custom extensions to each phase.
        This method shows how developers can extend the fuzzing capabilities.
        """
        print("\n[*] Demonstrating Custom Extensions...")

        # Example: Add custom frame delimiters for proprietary protocols
        self.add_custom_frame_delimiter(0x5A, 0xA5, "Proprietary Frame [5A...A5]")
        self.add_custom_frame_delimiter(0x12, 0x34, "Custom Protocol [12...34]")

        # Example: Add custom checksum algorithm (CRC-like)
        def custom_crc(data):
            crc = 0xFF
            for byte in data:
                crc ^= byte
                for _ in range(8):
                    if crc & 0x80:
                        crc = (crc << 1) ^ 0x07
                    else:
                        crc <<= 1
                    crc &= 0xFF
            return crc

        self.add_custom_checksum_algorithm(custom_crc, "Custom CRC-8")

        # Example: Add custom protocol patterns for specific medical devices
        # Blood pressure monitor pattern
        # self.add_custom_protocol_pattern([0xBP], "Blood Pressure CMD", [0x0D], 6)

        # Pulse oximeter pattern
        # self.add_custom_protocol_pattern([0xO2, 0x01], "Pulse Ox Query", [0x03], 4)

        # ECG device pattern
        # self.add_custom_protocol_pattern([0xEC, 0xG0], "ECG Command", [], 8)

        print("[+] Custom extensions added:")
        print("    - 2 custom frame delimiters")
        print("    - 1 custom checksum algorithm (CRC-8)")
        print("    - 3 custom protocol patterns for medical devices")

    def load_custom_patterns_from_file(self, filename):
        """
        Load custom patterns from a JSON configuration file.

        Expected format:
        {
            "frame_delimiters": [
                {"start": 90, "end": 165, "description": "Custom Frame"}
            ],
            "protocol_patterns": [
                {
                    "prefix": [0xBP],
                    "name": "Blood Pressure",
                    "suffix": [13],
                    "max_payload": 6
                }
            ]
        }
        """
        try:
            with open(filename, "r") as f:
                config = json.load(f)

            # Load frame delimiters
            for delimiter in config.get("frame_delimiters", []):
                self.add_custom_frame_delimiter(
                    delimiter["start"],
                    delimiter["end"],
                    delimiter.get("description", "Loaded delimiter"),
                )

            # Load protocol patterns
            for pattern in config.get("protocol_patterns", []):
                self.add_custom_protocol_pattern(
                    pattern["prefix"],
                    pattern["suffix"],
                    pattern["name"],
                    pattern.get("max_payload", 8),
                )

            print(f"[+] Loaded custom patterns from {filename}")
            if self.logger:
                self.logger.log_info("CUSTOM_LOAD", f"Loaded patterns from {filename}")

        except Exception as e:
            print(f"[-] Failed to load custom patterns: {e}")
            if self.logger:
                self.logger.log_info("CUSTOM_LOAD_ERROR", f"Failed to load from {filename}: {e}")

    def save_successful_patterns_as_customs(self, filename):
        """
        Save successful command patterns as custom patterns for future use.
        This analyzes successful commands and extracts reusable patterns.
        """
        if not self.successful_commands:
            print("[-] No successful commands to analyze for patterns")
            return

        # Analyze successful commands for patterns
        custom_config = {"frame_delimiters": [], "protocol_patterns": []}

        # Extract patterns from successful commands
        pattern_analysis = {}
        for cmd in self.successful_commands:
            command_bytes = bytes.fromhex(cmd["command"].replace(" ", ""))
            if len(command_bytes) >= 3:
                # Look for potential frame patterns (same start/end bytes)
                if command_bytes[0] == command_bytes[-1]:
                    delimiter = (command_bytes[0], command_bytes[-1])
                    pattern_analysis.setdefault("delimiters", set()).add(delimiter)

                # Look for common prefixes
                prefix = command_bytes[:2] if len(command_bytes) >= 2 else command_bytes[:1]
                pattern_analysis.setdefault("prefixes", {}).setdefault(tuple(prefix), []).append(
                    cmd
                )

        # Convert to configuration format
        if "delimiters" in pattern_analysis:
            for start, end in pattern_analysis["delimiters"]:
                custom_config["frame_delimiters"].append(
                    {
                        "start": start,
                        "end": end,
                        "description": f"Extracted delimiter [{start:02X}...{end:02X}]",
                    }
                )

        if "prefixes" in pattern_analysis:
            for prefix, commands in pattern_analysis["prefixes"].items():
                if len(commands) >= 2:  # Only if pattern appears multiple times
                    custom_config["protocol_patterns"].append(
                        {
                            "prefix": list(prefix),
                            "name": f"Extracted pattern {prefix[0]:02X}",
                            "suffix": [],
                            "max_payload": 8,
                        }
                    )

        # Save to file
        try:
            with open(filename, "w") as f:
                json.dump(custom_config, f, indent=2)

            print(
                f"[+] Saved {len(custom_config['frame_delimiters'])} delimiters and {len(custom_config['protocol_patterns'])} patterns to {filename}"
            )
            if self.logger:
                self.logger.log_info("PATTERN_EXTRACT", f"Extracted patterns saved to {filename}")

        except Exception as e:
            print(f"[-] Failed to save patterns: {e}")
            if self.logger:
                self.logger.log_info("PATTERN_EXTRACT_ERROR", f"Save failed: {e}")

    def generate_frame_variants(self, base_command):
        """Generates variants of a command with common frame delimiters."""
        variants = []

        # Standard delimiters
        delimiters = [
            (0x7E, 0x7E, "HDLC Frame"),
            (0x02, 0x03, "STX/ETX Frame"),
            (0x01, 0x04, "SOH/EOT Frame"),
            (0xAA, 0x55, "Sync Pattern"),
            (0xFF, 0x00, "Marker Frame"),
            (0x10, 0x03, "DLE/ETX Frame"),
            (0xC0, 0xC0, "SLIP Frame"),
        ]

        # Add custom delimiters if any
        if hasattr(self, "_custom_delimiters"):
            delimiters.extend(self._custom_delimiters)

        base_bytes = bytes.fromhex(base_command.replace(" ", ""))

        for start, end, desc in delimiters:
            # Basic frame
            frame = bytes([start]) + base_bytes + bytes([end])
            variants.append((" ".join(f"{b:02X}" for b in frame), desc))

            # Frame with length byte
            if len(base_bytes) < 255:
                frame_with_len = bytes([start, len(base_bytes)]) + base_bytes + bytes([end])
                variants.append((" ".join(f"{b:02X}" for b in frame_with_len), f"{desc} w/ Length"))

        return variants

    def generate_checksum_variants(self, base_command):
        """Generates variants of a command with common checksums."""
        variants = []
        base_bytes = bytes.fromhex(base_command.replace(" ", ""))

        # Standard checksums
        checksums = [
            (lambda data: sum(data) % 256, "XOR checksum"),
            (lambda data: sum(data) & 0xFF, "SUM checksum"),
            (lambda data: (~sum(data) + 1) & 0xFF, "2's complement"),
            (lambda data: sum(data) ^ 0xFF, "Inverted SUM"),
            (lambda data: len(data) & 0xFF, "Length checksum"),
        ]

        # Add custom checksums if any
        if hasattr(self, "_custom_checksums"):
            checksums.extend(self._custom_checksums)

        for checksum_func, desc in checksums:
            try:
                checksum = checksum_func(base_bytes)
                variants.append(
                    (" ".join(f"{b:02X}" for b in base_bytes + bytes([checksum])), f"With {desc}")
                )
            except Exception as e:
                if self.logger:
                    self.logger.log_info("CHECKSUM_ERROR", f"Error with {desc}: {e}")

        return variants

    def generate_sequence_variants(self, base_command):
        """Generates variants with a sequence number."""
        variants = []
        base_bytes = bytes.fromhex(base_command.replace(" ", ""))

        for seq in range(0x00, 0x10):  # Test sequence numbers 0-15
            # Sequence at start
            variants.append(
                (" ".join(f"{b:02X}" for b in bytes([seq]) + base_bytes), f"Seq {seq:02X} at start")
            )
            # Sequence at end
            variants.append(
                (" ".join(f"{b:02X}" for b in base_bytes + bytes([seq])), f"Seq {seq:02X} at end")
            )

        return variants

    def fuzz_phase1_boofuzz(
        self,
        iterations=1000,
        test_count_offset=0,
        max_depth=1,
        verbose=False,
    ):
        """Phase 1: Protocol Grammar Fuzzing using boofuzz.

        Args:
            iterations: Requested number of test cases.
            test_count_offset: Current global test count.
            max_depth: Combinatorial depth for boofuzz. ``1`` fuzzes one field at a
                time; higher values enable cross-field combinations and greatly
                increase total mutations.
        """
        if not _BOOFUZZ_AVAILABLE:
            print(
                "[!] boofuzz not installed. Install with 'pip install -r requirements.txt' to enable protocol fuzzing."
            )
            return [], test_count_offset

        if self.logger:
            self.logger.log_info(
                "FUZZ_PHASE1_START",
                "Starting Phase 1: Protocol Grammar Fuzz",
                {"iterations": iterations},
            )

        if verbose:
            print(f"[VERBOSE] Requested max tests: {iterations}")
            print(f"[VERBOSE] Using boofuzz max_depth={max_depth}")

        print("[*] Phase 1: Protocol Grammar Fuzzing with boofuzz")

        
        # --- Phase 1 Callbacks: Health Check & Restart ---
        ep0_every = int(os.getenv("EP0_CHECK_EVERY", "5")) or 1
        _case_counter = {"n": 0}

        def _after_case_health_check(
            target,
            fuzz_data_logger,
            session,
            test_case_context=None,
            sock=None,
            *args,
            **kwargs,
        ):
            _case_counter["n"] += 1
            if _case_counter["n"] % ep0_every:
                return True
            ok = check_usb_link_and_endpoints(
                logger=getattr(self, "logger", None),
                port=getattr(self.serial_port, "port", None),
            )
            if ok:
                try:
                    fuzz_data_logger.log_info("USB link+endpoints: OK")
                except Exception:
                    pass
                return True
            try:
                fuzz_data_logger.log_fail("USB link+endpoints: FAIL")
            except Exception:
                pass
            return False

        def _restart_device_callback(
            target, fuzz_data_logger, session, sock=None, *args, **kwargs
        ):
            """Soft-restart the serial target: close/open; try to clear buffers."""
            _t = sock or target
            try:
                try:
                    _t.close()
                except Exception:
                    pass
                time.sleep(0.2)
                try:
                    _t.open()
                except Exception:
                    pass

                try:
                    if getattr(self, "serial_port", None):
                        try:
                            self.serial_port.reset_input_buffer()
                            self.serial_port.reset_output_buffer()
                        except Exception:
                            pass
                        try:
                            self.serial_port.setDTR(False)
                            time.sleep(0.05)
                            self.serial_port.setDTR(True)
                            time.sleep(0.15)
                        except Exception:
                            pass
                except Exception:
                    pass

                if hasattr(self, "logger") and self.logger:
                    self.logger.log_info(
                        "RESTART_DONE",
                        "Serial target restart attempted (close/open + buffers cleared)",
                    )
            except Exception as e:
                if hasattr(self, "logger") and self.logger:
                    self.logger.log_error("RESTART_EXCEPTION", f"{e}")
        session, target = build_fuzz_session(
            self.serial_port.port,
            self.serial_port.baudrate,
            pre_send_callbacks=None,
            post_test_case_callbacks=None,
            restart_callbacks=[_restart_device_callback],
        )
        if session is None:
            return [], test_count_offset
        session.register_post_test_case_callback(_after_case_health_check)

        total_cases = session.num_mutations(max_depth=max_depth)
        if verbose:
            print(f"[VERBOSE] boofuzz available mutations: {total_cases}")

        if total_cases and max_depth == 1:
            cases_to_run = min(iterations, total_cases)
        else:
            # For depth >1 the mutation space grows rapidly; limit via iterations.
            cases_to_run = iterations

        session._index_start = 0
        session._index_end = cases_to_run

        print(f"[+] Test Case 1/{iterations}")

        early_stop = None
        try:
            session.fuzz(max_depth=max_depth)
        except Exception as e:  # pragma: no cover - best effort
            early_stop = str(e)
            if verbose:
                print(f"[VERBOSE] Early stop: {early_stop}")

        executed = session.total_mutant_index
        remaining = iterations - executed
        if remaining > 0:
            if verbose:
                print(
                    f"[VERBOSE] Grammar exhausted after {executed} cases; generating {remaining} random cases"
                )
            if self.serial_port and self.serial_port.is_open:
                for i in range(remaining):
                    print(f"[+] Test Case {executed + i + 1}/{iterations}")
                    length = random.randint(0, 255)
                    cmd = random.randint(0, 255)
                    payload = bytes(random.getrandbits(8) for _ in range(length))
                    checksum = (length ^ cmd ^ sum(payload)) & 0xFF
                    frame = bytes([0x02, length, cmd]) + payload + bytes([checksum, 0x03])
                    try:
                        self.serial_port.write(frame)
                        self.serial_port.flush()
                    except Exception as e:  # pragma: no cover - best effort
                        if verbose:
                            print(f"[VERBOSE] Fallback send error: {e}")
                        break
            else:
                if verbose:
                    print("[VERBOSE] Serial port not available for fallback mutations")

        total_run = executed + max(0, remaining)
        phase_stats = {
            "phase": 1,
            "tests_run": total_run,
            "successful_responses": 0,
            "success_rate": 0.0,
        }

        if verbose and not early_stop:
            print("[VERBOSE] No early stop condition encountered")

        if self.logger:
            self.logger.log_info("FUZZ_PHASE1_COMPLETE", "Phase 1 complete", phase_stats)

        print("\n[*] Phase 1 Complete:")
        print(f"    Tests run: {total_run}")
        print("    Successful: 0")
        print("    Success rate: 0.00%")

        return [], test_count_offset + total_run

    def fuzz_phase2_random(self, max_tests=200, test_count_offset=0):
        """
        Phase 2: Random Fuzzing
        Generates completely random commands of varying lengths to discover unexpected responses.
        """
        if self.logger:
            self.logger.log_info(
                "FUZZ_PHASE2_START", "Starting Phase 2: Random Fuzzing", {"max_tests": max_tests}
            )

        print("\n[*] Phase 2: Random Fuzzing")
        print(f"    - Testing up to {max_tests} random commands")
        print("    - Variable length payloads (1-8 bytes)")
        print("    - Completely random byte sequences")

        test_count = test_count_offset
        successful_count = 0
        phase_successful_commands = []

        for i in range(max_tests):
            test_count += 1

            # Generate random command
            cmd_length = random.randint(1, 8)
            hex_cmd = " ".join(f"{b:02X}" for b in os.urandom(cmd_length))

            response = self.send_hex_command(
                hex_cmd, f"Random {cmd_length}B", verbose=False, test_phase="phase2_random"
            )

            if response:
                successful_count += 1
                phase_successful_commands.append(
                    {
                        "command": hex_cmd,
                        "description": f"Random {cmd_length}B",
                        "response": response,
                        "command_length": cmd_length,
                        "test_number": test_count,
                    }
                )
                print(f"[+] RANDOM SUCCESS [{test_count:03d}]: {hex_cmd}")
                print(f"    Response: {response}")
            elif test_count % 25 == 0:
                print(
                    f"[.] Random testing in progress... ({test_count - test_count_offset}/{max_tests})"
                )

            time.sleep(0.03)  # Shorter delay for random testing

        phase_stats = {
            "phase": 2,
            "tests_run": max_tests,
            "successful_responses": successful_count,
            "success_rate": successful_count / max_tests * 100 if max_tests > 0 else 0,
            "avg_command_length": (
                sum(len(cmd["command"].replace(" ", "")) // 2 for cmd in phase_successful_commands)
                / len(phase_successful_commands)
                if phase_successful_commands
                else 0
            ),
        }

        if self.logger:
            self.logger.log_info("FUZZ_PHASE2_COMPLETE", "Phase 2 complete", phase_stats)

        print("\n[*] Phase 2 Complete:")
        print(f"    Tests run: {max_tests}")
        print(f"    Successful: {successful_count}")
        print(f"    Success rate: {successful_count / max_tests * 100:.2f}%")

        return phase_successful_commands, test_count

    def fuzz_phase3_protocol_specific(self, max_tests=None, test_count_offset=0):
        """
        Phase 3: Protocol-Specific Fuzzing
        Tests medical device specific patterns and known protocol structures.
        """
        if self.logger:
            self.logger.log_info(
                "FUZZ_PHASE3_START", "Starting Phase 3: Protocol-Specific", {"max_tests": max_tests}
            )

        print("\n[*] Phase 3: Protocol-Specific Fuzzing")
        print("    - Medical device specific patterns")
        print("    - Known protocol structures (STX/ETX, SOH, Command codes)")
        print("    - Variable payload lengths per pattern")

        # Phase 3 pattern catalog (protocol-specific framing/prefixes).
        # Byte layout convention used below:
        #   [PREFIX...][PAYLOAD (0..max_payload_len bytes)][SUFFIX...]
        # Field assumptions:
        #   - PREFIX: sync/header/command bytes (e.g., STX/SOH, CMD80/CMD82, AA55 markers)
        #   - PAYLOAD: optional params/data (mutated/random/structured in _generate_structured_payload)
        #   - SUFFIX: end delimiter or framing tail (e.g., ETX, 0x7E, SLIP 0xC0)
        # Report/JSON mapping:
        #   - send_hex_command(..., test_phase="phase3_protocol") tags commands.json entries
        #   - successful results store pattern_name + payload_length in phase3_results
        #     (used by analysis_report.txt grouping via test_phase)
        # Define standard medical device patterns
        medical_patterns = [
            # (prefix_bytes, pattern_name, suffix_bytes, max_payload_len)
            ([0x02], "STX + CMD + ETX", [0x03], 8),
            ([0x01], "SOH + CMD + ETX", [0x03], 8),
            ([0x80], "CMD80 + param", [], 6),
            ([0x81], "CMD81 + param", [], 6),
            ([0x82], "CMD82 + param", [], 6),
            ([0x90], "CMD90 + param", [], 6),
            ([0x91], "CMD91 + param", [], 6),
            ([0x7E], "Frame + data + 7E", [0x7E], 8),
            ([0xAA, 0x55], "Sync + data", [], 6),
            ([0xFF, 0x00], "Marker + data", [], 6),
            ([0x10], "DLE + data + ETX", [0x03], 6),
            ([0xC0], "SLIP frame + data", [0xC0], 8),
            # Additional medical device patterns
            ([0x06], "ACK + data", [], 4),
            ([0x15], "NAK + data", [], 4),
            ([0x04], "EOT + data", [], 4),
            ([0x05], "ENQ", [], 0),
            ([0x7F], "DEL frame", [0x7F], 6),
            # Blood glucose meter patterns
            ([0x51], "Query command", [], 4),
            ([0x49], "Info command", [], 4),
            ([0x53], "Status command", [], 4),
            # Generic device commands
            ([0xA0], "CMDA0 + param", [], 6),
            ([0xA1], "CMDA1 + param", [], 6),
            ([0xB0], "CMDB0 + param", [], 6),
            ([0xC1], "CMDC1 + param", [], 6),
        ]

        # Add custom patterns if any
        if hasattr(self, "_custom_patterns"):
            medical_patterns.extend(self._custom_patterns)
            print(f"    - Including {len(self._custom_patterns)} custom patterns")

        test_count = test_count_offset
        successful_count = 0
        phase_successful_commands = []
        pattern_stats = {}

        remaining_tests = max_tests - test_count_offset if max_tests else float("inf")
        tests_per_pattern = max(1, remaining_tests // len(medical_patterns)) if max_tests else 30

        for prefix, pattern_name, suffix, max_payload_len in medical_patterns:
            if max_tests and test_count >= max_tests:
                break

            print(f"\n[+] Testing pattern: {pattern_name}")
            pattern_successful = 0
            pattern_total = 0

            # Test different payload lengths for this pattern
            for data_len in range(0, min(max_payload_len + 1, 9)):
                if max_tests and test_count >= max_tests:
                    break

                # Generate multiple test cases for each length
                tests_for_this_length = min(int(tests_per_pattern // (max_payload_len + 1)), 10)
                if tests_for_this_length < 1:
                    tests_for_this_length = 1

                for _ in range(tests_for_this_length):
                    if max_tests and test_count >= max_tests:
                        break

                    test_count += 1
                    pattern_total += 1

                    # Generate payload with some intelligence
                    if data_len == 0:
                        payload = b""
                    else:
                        # Mix random data with some structured data
                        if random.random() < 0.3:  # 30% chance of structured data
                            payload = self._generate_structured_payload(data_len)
                        else:
                            payload = os.urandom(data_len)

                    # Construct full command (layout: PREFIX + PAYLOAD + SUFFIX)
                    full_cmd_bytes = bytes(prefix) + payload + bytes(suffix)
                    hex_cmd = " ".join(f"{b:02X}" for b in full_cmd_bytes)

                    response = self.send_hex_command(
                        hex_cmd,
                        f"{pattern_name}({data_len}B)",
                        verbose=False,
                        # test_phase label is used by analysis_report.txt and commands.json
                        test_phase="phase3_protocol",
                    )

                    if response:
                        successful_count += 1
                        pattern_successful += 1
                        phase_successful_commands.append(
                            {
                                "command": hex_cmd,
                                "description": f"{pattern_name}({data_len}B)",
                                "response": response,
                                "pattern_name": pattern_name,
                                "payload_length": data_len,
                                "prefix": prefix,
                                "suffix": suffix,
                                "test_number": test_count,
                            }
                        )
                        print(f"[+] SUCCESS [{test_count:03d}] {pattern_name}: {hex_cmd}")
                        print(f"    Response: {response}")

                    time.sleep(0.03)

            # Store pattern statistics
            pattern_stats[pattern_name] = {
                "total_tests": pattern_total,
                "successful": pattern_successful,
                "success_rate": (
                    pattern_successful / pattern_total * 100 if pattern_total > 0 else 0
                ),
            }

            if pattern_successful > 0:
                print(
                    f"    Pattern '{pattern_name}': {pattern_successful}/{pattern_total} successful ({pattern_successful/pattern_total*100:.1f}%)"
                )

        phase_stats = {
            "phase": 3,
            "tests_run": test_count - test_count_offset,
            "successful_responses": successful_count,
            "success_rate": (
                successful_count / (test_count - test_count_offset) * 100
                if test_count > test_count_offset
                else 0
            ),
            "patterns_tested": len(medical_patterns),
            "pattern_breakdown": pattern_stats,
        }

        if self.logger:
            self.logger.log_info("FUZZ_PHASE3_COMPLETE", "Phase 3 complete", phase_stats)

        print("\n[*] Phase 3 Complete:")
        print(f"    Tests run: {test_count - test_count_offset}")
        print(f"    Successful: {successful_count}")
        if test_count > test_count_offset:
            print(
                f"    Success rate: {successful_count / (test_count - test_count_offset) * 100:.2f}%"
            )

        # Show pattern summary
        successful_patterns = [
            name for name, stats in pattern_stats.items() if stats["successful"] > 0
        ]
        if successful_patterns:
            print(f"    Successful patterns: {', '.join(successful_patterns)}")

        return phase_successful_commands, test_count

    def _generate_structured_payload(self, length):
        """Generate structured payload data for more intelligent fuzzing."""
        if length == 1:
            # Single byte - common command codes or values
            candidates = [0x00, 0x01, 0x02, 0x03, 0xFF, 0xAA, 0x55, 0x80, 0x81, 0x90, 0x91]
            return bytes([random.choice(candidates)])
        elif length == 2:
            # Two bytes - could be length + data, or 16-bit values
            if random.random() < 0.5:
                return bytes([random.randint(0, length), random.randint(0, 255)])
            else:
                # Common 16-bit patterns
                return random.choice([b"\x00\x00", b"\xff\xff", b"\x01\x00", b"\x00\x01"]).ljust(
                    length, b"\x00"
                )
        else:
            # Longer payloads - mix of structured and random
            structured = []
            # Maybe start with length
            if random.random() < 0.3:
                structured.append(length - 1)
            # Add some common values
            for _ in range(min(2, length - len(structured))):
                if random.random() < 0.4:
                    structured.append(random.choice([0x00, 0x01, 0xFF, 0xAA, 0x55]))
                else:
                    structured.append(random.randint(0, 255))
            # Fill remaining with random
            while len(structured) < length:
                structured.append(random.randint(0, 255))
            return bytes(structured)

    def fuzz_test_baudrate(
        self, baudrate, max_tests=500, phases=None, verbose=False, fuzz_depth=1
    ):
        """
        Main fuzz testing coordinator that can run individual phases or all phases.

        Args:
            baudrate: Serial baudrate to test
            max_tests: Maximum total tests across all phases
            phases: List of phases to run (e.g., [1, 2, 3] or [2] for random only)
            fuzz_depth: boofuzz "max_depth" controlling combinatorial fuzzing
        """
        if phases is None:
            phases = [1, 2, 3]  # Run all phases by default

        if self.logger:
            self.logger.log_info(
                "FUZZ_START",
                f"Starting fuzz test for {baudrate} baud",
                {
                    "baudrate": baudrate,
                    "max_tests": max_tests,
                    "phases": phases,
                },
            )

        print(f"\n[*] Starting fuzz test for {baudrate} baud")
        print(f"[*] Max test cases: {max_tests}")
        print(f"[*] Phases to run: {phases}")
        print(f"[*] Boofuzz max_depth: {fuzz_depth}")
        if verbose:
            print("[*] Verbose mode enabled")
        print("=" * 60)

        if not self.setup_serial(baudrate):
            return []

        self.start_usb_monitoring()
        self.successful_commands = []

        total_test_count = 0
        total_successful_count = 0
        all_phase_results = []

        # Distribute tests across phases
        if len(phases) == 3:
            phase1_max = max_tests // 2  # 50% for variants
            phase2_max = min(200, max_tests // 4)  # 25% for random (max 200)
        elif len(phases) == 2:
            phase1_max = phase2_max = max_tests // 2
        else:
            phase1_max = phase2_max = max_tests

        # Run Phase 1: Protocol Grammar Fuzzing
        if 1 in phases:
            phase1_results, total_test_count = self.fuzz_phase1_boofuzz(
                min(phase1_max, max_tests),
                total_test_count,
                max_depth=fuzz_depth,
                verbose=verbose,
            )
            all_phase_results.extend(phase1_results)
            total_successful_count += len(phase1_results)

        # Run Phase 2: Random Fuzzing
        if 2 in phases and total_test_count < max_tests:
            remaining_tests = max_tests - total_test_count
            phase2_tests = min(phase2_max, remaining_tests)
            phase2_results, total_test_count = self.fuzz_phase2_random(
                phase2_tests, total_test_count
            )
            all_phase_results.extend(phase2_results)
            total_successful_count += len(phase2_results)

        # Run Phase 3: Protocol-Specific
        if 3 in phases and total_test_count < max_tests:
            remaining_tests = max_tests - total_test_count
            phase3_results, total_test_count = self.fuzz_phase3_protocol_specific(
                remaining_tests, total_test_count
            )
            all_phase_results.extend(phase3_results)
            total_successful_count += len(phase3_results)

        time.sleep(2)
        self.stop_usb_monitoring()

        # Update statistics
        stats = {
            "total_tests": total_test_count,
            "successful_responses": total_successful_count,
            "success_rate": (
                total_successful_count / total_test_count * 100 if total_test_count > 0 else 0
            ),
            "baudrate_tested": baudrate,
            "phases_run": phases,
        }

        if self.logger:
            self.logger.update_statistics(stats)
            self.logger.log_info("FUZZ_COMPLETE", "All phases complete", stats)

        print("\n" + "=" * 60)
        print(f"[+] Fuzz testing complete for {baudrate} baud")
        print("[*] Overall Statistics:")
        print(f"    Total tests: {total_test_count}")
        print(f"    Successful responses: {total_successful_count}")
        if total_test_count > 0:
            print(f"    Overall success rate: {total_successful_count/total_test_count*100:.2f}%")
        print(f"    Phases completed: {phases}")

        # Store all results in the main successful_commands list
        self.successful_commands.extend(all_phase_results)

        return self.successful_commands

    def test_common_protocols(self):
        """Tests a list of common medical device protocols."""
        test_commands = [
            ("02", "STX"),
            ("03", "ETX"),
            ("04", "EOT"),
            ("06", "ACK"),
            ("15", "NAK"),
            ("02 51 03", "Query ('Q')"),
            ("02 49 03", "Info ('I')"),
            ("02 53 03", "Status ('S')"),
            ("41 54 0D", "AT<CR>"),
            ("41 54 49 0D", "ATI<CR>"),
            ("AA 55", "Sync pattern"),
            ("7E 01 02 03 7E", "Frame with delimiters"),
            ("80 01", "Command 0x80"),
        ]

        if self.logger:
            self.logger.log_info(
                "PROTOCOL_TEST_START", f"Testing {len(test_commands)} common protocols"
            )

        print("[*] Testing common protocols...")
        print("=" * 50)
        responses = []
        for hex_cmd, desc in test_commands:
            print(f"\n[*] Testing: {desc}")
            response = self.send_hex_command(hex_cmd, desc, test_phase="protocol_test")
            if response:
                responses.append((desc, hex_cmd, response))
                print("[+] Response received!")
            else:
                print("[.] No response.")
            time.sleep(0.5)

        if self.logger:
            self.logger.log_info(
                "PROTOCOL_TEST_COMPLETE", f"Protocol test complete: {len(responses)} successful"
            )

        return responses

    def analyze_usb_data(self):
        """Analyzes and summarizes captured USB data."""
        if not self.usb_data:
            print("[*] No USB data captured.")
            if self.logger:
                self.logger.log_info("USB_ANALYSIS", "No USB data to analyze")
            return

        print(f"\n[*] USB Data Analysis ({len(self.usb_data)} records)")
        print("=" * 60)
        bulk_in, bulk_out = [], []
        for timestamp, line in self.usb_data:
            if len(bulk_in) + len(bulk_out) < 50:
                print(f"[{timestamp}] {line}")
            if "Bo:" in line and "=" in line:
                hex_match = line.split("=")[-1].strip()
                if hex_match:
                    bulk_out.append((timestamp, hex_match))
            elif "Bi:" in line and "=" in line:
                hex_match = line.split("=")[-1].strip()
                if hex_match:
                    bulk_in.append((timestamp, hex_match))

        print("\n[*] Data Summary:")
        print(f"    Sent packets (Bulk Out): {len(bulk_out)}")
        print(f"    Received packets (Bulk In): {len(bulk_in)}")

        if bulk_out:
            print("\n[*] Sent Data (first 10):")
            for ts, data in bulk_out[:10]:
                print(f"    [{ts}] {data} | {self.hex_to_ascii_safe(data)}")
        if bulk_in:
            print("\n[*] Received Data (all):")
            for ts, data in bulk_in:
                print(f"    [{ts}] {data} | {self.hex_to_ascii_safe(data)}")

        if self.logger:
            self.logger.log_info(
                "USB_ANALYSIS",
                "USB data analysis complete",
                {
                    "total_packets": len(self.usb_data),
                    "bulk_out": len(bulk_out),
                    "bulk_in": len(bulk_in),
                },
            )

    def analyze_successful_commands(self):
        """Analyzes and groups successful commands by response."""
        if not self.successful_commands:
            print("[*] No successful commands to analyze.")
            if self.logger:
                self.logger.log_info("COMMAND_ANALYSIS", "No successful commands to analyze")
            return

        print(f"\n[*] Successful Command Analysis ({len(self.successful_commands)} commands)")
        print("=" * 60)

        response_groups = {}
        for cmd in self.successful_commands:
            response_hex = cmd["response"].split("|")[0].strip()
            response_groups.setdefault(response_hex, []).append(cmd)

        for resp_pattern, commands in response_groups.items():
            print(f"\n[+] Response Pattern: {resp_pattern}")
            print(f"    Triggered by: {len(commands)} commands")
            print("    Triggering Commands (first 5):")
            for i, cmd in enumerate(commands[:5], 1):
                print(f"      {i}. {cmd['command']} -> {cmd['response'][:50]}...")
            if len(commands) > 5:
                print(f"      ... and {len(commands) - 5} more.")

        print("\n[*] Command Length Distribution:")
        length_dist = {}
        for cmd in self.successful_commands:
            cmd_bytes = len(cmd["command"].replace(" ", "")) // 2
            length_dist[cmd_bytes] = length_dist.get(cmd_bytes, 0) + 1
        for length, count in sorted(length_dist.items()):
            print(f"    {length} bytes: {count} commands")

        # Response time analysis
        response_times = [
            cmd.get("response_time_ms", 0)
            for cmd in self.successful_commands
            if cmd.get("response_time_ms")
        ]
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            print("\n[*] Response Time Analysis:")
            print(f"    Average response time: {avg_response_time:.2f} ms")
            print(f"    Min response time: {min(response_times):.2f} ms")
            print(f"    Max response time: {max(response_times):.2f} ms")

        if self.logger:
            analysis_data = {
                "total_successful": len(self.successful_commands),
                "unique_responses": len(response_groups),
                "length_distribution": length_dist,
                "avg_response_time_ms": (
                    sum(response_times) / len(response_times) if response_times else 0
                ),
            }
            self.logger.log_info("COMMAND_ANALYSIS", "Command analysis complete", analysis_data)
            self.logger.session_data["analysis_results"] = analysis_data

    def hex_to_ascii_safe(self, hex_string):
        """Safely converts a hex string to a printable ASCII string."""
        try:
            hex_clean = hex_string.replace(" ", "")
            if len(hex_clean) % 2 != 0:
                return "Invalid format"
            bytes_data = bytes.fromhex(hex_clean)
            return "".join(chr(b) if 32 <= b <= 126 else "." for b in bytes_data)
        except Exception:
            return "Conversion failed"

    def interactive_mode(self):
        """Starts an interactive mode for manual command entry."""
        print("\n[+] Entering interactive mode.")
        print("    Enter hex command (e.g., 02 51 03) or 'quit' to exit.")
        print("    Special commands:")
        print("      'help' - Show this help")
        print("      'stats' - Show current session statistics")
        print("      'successful' - Show successful commands from this session")

        if self.logger:
            self.logger.log_info("INTERACTIVE_START", "Interactive mode started")

        command_count = 0
        while True:
            try:
                user_input = input("\nHEX > ").strip()
                if user_input.lower() in ["quit", "exit", "q"]:
                    break
                elif user_input.lower() == "help":
                    print("    Commands:")
                    print("      Enter hex bytes separated by spaces (e.g., 02 51 03)")
                    print("      'stats' - Show session statistics")
                    print("      'successful' - List successful commands")
                    print("      'quit' - Exit interactive mode")
                elif user_input.lower() == "stats":
                    print(f"    Commands sent this session: {command_count}")
                    print(f"    Successful responses: {len(self.successful_commands)}")
                    if command_count > 0:
                        print(
                            f"    Success rate: {len(self.successful_commands)/command_count*100:.1f}%"
                        )
                elif user_input.lower() == "successful":
                    if self.successful_commands:
                        print("    Successful commands:")
                        for i, cmd in enumerate(self.successful_commands[-10:], 1):  # Show last 10
                            print(f"      {i}. {cmd['command']} -> {cmd['response'][:50]}...")
                    else:
                        print("    No successful commands yet.")
                elif user_input:
                    command_count += 1
                    if not self.send_hex_command(
                        user_input, "Interactive command", test_phase="interactive"
                    ):
                        print("[.] No response.")
            except KeyboardInterrupt:
                break

        if self.logger:
            self.logger.log_info(
                "INTERACTIVE_END", f"Interactive mode ended after {command_count} commands"
            )

        print(f"\n[+] Exiting interactive mode. Sent {command_count} commands.")

    def export_successful_commands(self, filename=None):
        """Export successful commands to a file for further analysis."""
        if not self.successful_commands:
            print("[*] No successful commands to export.")
            return

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"successful_commands_{timestamp}.json"

        device_info = {"tty": self.tty_device}
        if self.bus and self.device:
            device_info["bus"] = self.bus
            device_info["device"] = self.device

        export_data = {
            "export_time": datetime.now().isoformat(),
            "device_info": device_info,
            "total_successful_commands": len(self.successful_commands),
            "commands": self.successful_commands,
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)
            print(f"[+] Exported {len(self.successful_commands)} successful commands to {filename}")
            if self.logger:
                self.logger.log_info("EXPORT", f"Commands exported to {filename}")
        except Exception as e:
            print(f"[-] Export failed: {e}")
            if self.logger:
                self.logger.log_info("EXPORT_ERROR", f"Export failed: {e}")


def find_serial_device():
    """Finds a serial device, prioritizing CP210x if available."""
    ports = list_ports.comports()
    if not ports:
        return None

    # Prioritize CP210x devices
    for port in ports:
        if "cp210x" in port.description.lower() or (port.vid == 0x10C4 and port.pid == 0xEA60):
            return port.device

    # Fallback to the first available serial port
    return ports[0].device


def main():
    print("--- Hex Protocol Monitor v7 (Kali Linux Hardened) ---")
    print(
        "A tool for reverse engineering serial protocols with intelligent fuzzing and comprehensive logging."
    )
    print("=" * 80)

    # Initialize session logger
    session_name = None
    if "--session" in sys.argv:
        try:
            session_index = sys.argv.index("--session")
            if session_index + 1 < len(sys.argv):
                session_name = sys.argv[session_index + 1]
        except (ValueError, IndexError):
            pass

    logger = SessionLogger(session_name)

    # --- Manual Port Specification ---
    tty_device = None
    if "--port" in sys.argv:
        try:
            port_index = sys.argv.index("--port")
            if port_index + 1 < len(sys.argv):
                tty_device = sys.argv[port_index + 1]
                print(f"[+] Using manually specified port: {tty_device}")
        except (ValueError, IndexError):
            pass  # Will fallback to auto-detection

    if not tty_device:
        tty_device = find_serial_device()
        if tty_device:
            print(f"[+] Serial device automatically found: {tty_device}")

    if not tty_device:
        logger.log_info(
            "ERROR", "No serial device found. Ensure it is connected or specify with --port <name>"
        )
        sys.exit(1)

    monitor = HexProtocolMonitor(tty_device, logger)

    command = "auto"
    if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        command = sys.argv[1]

    try:
        if command == "auto":
            logger.set_test_parameters({"mode": "auto", "baudrates": [9600, 19200, 38400, 115200]})
            baudrates = [9600, 19200, 38400, 115200]
            for baudrate in baudrates:
                print(f"[*] Testing baudrate: {baudrate}")
                if monitor.setup_serial(baudrate):
                    monitor.start_usb_monitoring()
                    responses = monitor.test_common_protocols()
                    time.sleep(2)
                    monitor.stop_usb_monitoring()
                    monitor.analyze_usb_data()
                    if responses:
                        print(
                            f"[+] Found {len(responses)} valid responses at {baudrate} baud! Fuzzing this baudrate is recommended."
                        )
                        logger.log_info(
                            "AUTO_SUCCESS",
                            f"Found working baudrate: {baudrate}",
                            {"responses": len(responses)},
                        )
                        break

        elif command == "fuzz":
            if len(sys.argv) < 3 or (len(sys.argv) >= 3 and sys.argv[2].startswith("--")):
                print("[-] Fuzz mode requires a baudrate.")
                print(
                    f"Usage: python3 {Path(__file__).name} fuzz <baudrate> [max_tests] [--phases 1,2,3] [--depth <n>] [--session <name>]"
                )
                sys.exit(1)
            baudrate = int(sys.argv[2])
            max_tests = 500
            phases = [1, 2, 3]  # Default: run all phases
            verbose = False
            fuzz_depth = 1

            # Parse additional parameters
            i = 3
            while i < len(sys.argv):
                arg = sys.argv[i]
                if arg == "--phases" and i + 1 < len(sys.argv):
                    try:
                        phases = [int(p.strip()) for p in sys.argv[i + 1].split(",")]
                        phases = [p for p in phases if p in [1, 2, 3]]  # Validate phases
                        if not phases:
                            phases = [1, 2, 3]
                        i += 2
                    except (ValueError, IndexError):
                        print("[-] Invalid phases format. Use: --phases 1,2,3")
                        sys.exit(1)
                elif arg == "--session":
                    i += 2  # Skip session parameter (already handled)
                elif arg == "--verbose":
                    verbose = True
                    i += 1
                elif arg == "--depth" and i + 1 < len(sys.argv):
                    try:
                        fuzz_depth = int(sys.argv[i + 1])
                        i += 2
                    except (ValueError, IndexError):
                        print("[-] Invalid depth value. Use an integer like 1 or 2")
                        sys.exit(1)
                elif arg.isdigit():
                    max_tests = int(arg)
                    i += 1
                else:
                    i += 1

            logger.set_test_parameters(
                {
                    "mode": "fuzz",
                    "baudrate": baudrate,
                    "max_tests": max_tests,
                    "phases": phases,
                    "verbose": verbose,
                    "fuzz_depth": fuzz_depth,
                }
            )
            monitor.fuzz_test_baudrate(
                baudrate,
                max_tests=max_tests,
                phases=phases,
                verbose=verbose,
                fuzz_depth=fuzz_depth,
            )
            monitor.analyze_usb_data()
            monitor.analyze_successful_commands()
            monitor.export_successful_commands()

        elif command == "interactive":
            baudrate = 9600

            # Parse baudrate, accounting for --session parameter
            for arg in sys.argv[2:]:
                if arg.isdigit():
                    baudrate = int(arg)
                    break

            logger.set_test_parameters({"mode": "interactive", "baudrate": baudrate})
            if monitor.setup_serial(baudrate):
                monitor.start_usb_monitoring()
                monitor.interactive_mode()
                monitor.stop_usb_monitoring()
                monitor.analyze_usb_data()
                monitor.analyze_successful_commands()

        else:
            script_name = Path(__file__).name
            print("Usage:")
            print(f"  python3 {script_name} auto [--port <name>] [--session <name>]")
            print(
                f"  python3 {script_name} fuzz <baudrate> [max_tests] [--phases 1,2,3] [--depth <n>] [--port <name>] [--session <name>]"
            )
            print(
                f"  python3 {script_name} interactive [baudrate] [--port <name>] [--session <name>]"
            )
            print("\nExamples:")
            print(f"  python3 {script_name} fuzz 19200 1000")
            print(
                f"  python3 {script_name} interactive 9600 --port COM3 --session glucose_meter_test"
            )
            print(f"  python3 {script_name} auto --port /dev/ttyUSB1 --session initial_scan")
            print("\nNew Features in v7 (Kali Hardened):")
            print("  • Enhanced serial port permission handling with clear user instructions.")
            print("  • Robust USB monitoring checks (requires 'sudo') with guidance.")
            print("  • Graceful feature degradation if permissions are insufficient.")
            print("  • Retains all features from v5.")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        logger.log_info("INTERRUPTED", "Session interrupted by user")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        logger.log_info("ERROR", f"Unexpected error: {e}")
    finally:
        if monitor.serial_port and monitor.serial_port.is_open:
            monitor.serial_port.close()

        # Finalize session and generate report
        logger.finalize_session()


if __name__ == "__main__":
    main()
