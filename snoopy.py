#!/usr/bin/env -S uv run -q
# /// script
# requires-python = ">=3.14"
# dependencies = [
#   "textual>=8.2.8",
# ]
# ///
"""Passive local-network reconnaissance with a Textual dashboard."""

from __future__ import annotations

import argparse
import ipaddress
import json
import queue
import shutil
import signal
import struct
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Final, Iterator

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, RichLog, Static

TCPDUMP_FILTER: Final[str] = (
    "(ether dst 01:00:0c:cc:cc:cc) or "
    "(ether proto 0x88cc) or "
    "(udp port 5353) or "
    "(udp port 137) or "
    "(udp port 1900) or "
    "(udp port 3702) or "
    "(ip proto 89) or "
    "(ip6 proto 89)"
)
TCPDUMP_SNAPLEN: Final[str] = "0"
PCAP_MAGIC_USEC: Final[int] = 0xA1B2C3D4
PCAP_MAGIC_NSEC: Final[int] = 0xA1B23C4D
ETH_P_8021Q: Final[int] = 0x8100
ETH_P_8021AD: Final[int] = 0x88A8
ETH_P_LLDP: Final[int] = 0x88CC
ETH_P_IPV4: Final[int] = 0x0800
ETH_P_IPV6: Final[int] = 0x86DD
OSPF_PROTOCOL: Final[int] = 89
MDNS_PORT: Final[int] = 5353
NBNS_PORT: Final[int] = 137
SSDP_PORT: Final[int] = 1900
WSD_PORT: Final[int] = 3702
LLC_SNAP_DSAP: Final[int] = 0xAA
LLC_SNAP_SSAP: Final[int] = 0xAA
SNAP_CISCO_OUI: Final[bytes] = b"\x00\x00\x0c"
SNAP_PID_CDP: Final[int] = 0x2000


class SnoopyError(RuntimeError):
    """Raised when snoopy cannot start or decode required input."""


@dataclass(frozen=True)
class PacketContext:
    """Common packet metadata extracted from the link and network layers."""

    src_mac: str
    dst_mac: str
    src_ip: str | None = None
    dst_ip: str | None = None


@dataclass(frozen=True)
class Event:
    """A decoded discovery event ready for display and de-duplication."""

    protocol: str
    summary: str
    dedupe_key: str
    identity: str
    source_mac: str
    source_ip: str
    location: str
    details: str


@dataclass(frozen=True)
class DiscoveryRecord:
    """Dashboard state for a unique discovery target."""

    protocol: str
    identity: str
    source_mac: str
    source_ip: str
    location: str
    details: str
    dedupe_key: str
    first_seen: datetime
    last_seen: datetime
    seen_count: int
    summary: str


@dataclass(frozen=True)
class PcapConfig:
    """pcap stream byte-order configuration."""

    endian: str


@dataclass(frozen=True)
class ControlMessage:
    """Message emitted from the capture thread to the dashboard."""

    kind: str
    payload: Event | str | None = None


class CaptureSession:
    """Own the tcpdump subprocess and stream structured events from it."""

    def __init__(self, interface: str, count: int | None) -> None:
        self.interface = interface
        self.count = count
        self._process: subprocess.Popen[bytes] | None = None
        self._stop_requested = threading.Event()

    def stop(self) -> None:
        """Request that the capture subprocess stop."""

        self._stop_requested.set()
        if self._process is not None and self._process.poll() is None:
            self._process.send_signal(signal.SIGINT)

    def iter_events(self) -> Iterator[Event]:
        """Start tcpdump and yield decoded discovery events."""

        tcpdump_path = require_tcpdump()
        command = [
            tcpdump_path,
            "-i",
            self.interface,
            "-n",
            "-U",
            "-s",
            TCPDUMP_SNAPLEN,
            "-w",
            "-",
            TCPDUMP_FILTER,
        ]

        try:
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise SnoopyError(f"Failed to start tcpdump: {exc}") from exc

        if self._process.stdout is None or self._process.stderr is None:
            self._process.kill()
            raise SnoopyError("Failed to capture tcpdump output streams.")

        emitted = 0
        try:
            for packet in iter_pcap_packets(self._process.stdout):
                if self._stop_requested.is_set():
                    break
                for event in extract_events(packet):
                    yield event
                    emitted += 1
                    if self.count is not None and emitted >= self.count:
                        self.stop()
                        break
                if self.count is not None and emitted >= self.count:
                    break
        except EOFError:
            pass
        finally:
            if self._process.poll() is None:
                self._process.terminate()
            stderr_output = (
                self._process.stderr.read().decode("utf-8", errors="replace").strip()
            )
            return_code = self._process.wait()
            if not self._stop_requested.is_set() and return_code not in {
                0,
                -signal.SIGINT,
                130,
                143,
            }:
                raise SnoopyError(
                    "tcpdump exited unsuccessfully. "
                    f"Make sure you have permission to capture packets on {self.interface!r}. "
                    f"Details: {stderr_output or 'no stderr output'}"
                )


class SnoopyDashboard(App[None]):
    """Textual dashboard for passive local-network discovery."""

    COLUMN_LABELS: Final[dict[str, str]] = {
        "protocol": "Protocol",
        "identity": "Identity",
        "source_ip": "Source IP",
        "source_mac": "Source MAC",
        "location": "Location",
        "seen_count": "Seen",
        "last_seen": "Last Seen",
        "details": "Details",
    }

    CSS = """
    Screen {
        background: #09111a;
        color: #edf2f7;
    }

    #main {
        height: 1fr;
        padding: 1 2;
    }

    #left-pane, #right-pane {
        height: 1fr;
        border: round #2f5b72;
        background: #0f1f2c;
        padding: 1;
    }

    #left-pane {
        width: 2fr;
        margin-right: 1;
    }

    #right-pane {
        width: 1fr;
        display: none;
    }

    #status, #summary {
        padding: 0 1;
        margin-bottom: 1;
        color: #d5e5ef;
    }

    #status {
        background: #173042;
        border: heavy #3f708a;
    }

    #summary {
        background: #102433;
        border: solid #2d5369;
        height: 4;
    }

    #devices-title, #details-title, #events-title {
        color: #9ad0e3;
        text-style: bold;
        margin-bottom: 1;
    }

    DataTable {
        height: 1fr;
    }

    #details-pane {
        height: 14;
        margin-top: 1;
        background: #0b1620;
        color: #edf2f7;
        border: solid #26485d;
    }

    #events-log {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("s", "save_devices", "Save JSON"),
        ("l", "toggle_log", "Toggle Log"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, interface: str, count: int | None) -> None:
        super().__init__()
        self.interface = interface
        self.count = count
        self.capture_session = CaptureSession(interface=interface, count=count)
        self.message_queue: queue.SimpleQueue[ControlMessage] = queue.SimpleQueue()
        self.capture_thread: threading.Thread | None = None
        self.records: dict[str, DiscoveryRecord] = {}
        self.protocol_counts: Counter[str] = Counter()
        self.total_events = 0
        self.started_at = datetime.now()
        self.status_message = "Starting capture..."
        self.selected_record_key: str | None = None
        self.sort_column = "last_seen"
        self.sort_reverse = True

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout."""

        yield Header(show_clock=True)
        with Horizontal(id="main"):
            with Vertical(id="left-pane"):
                yield Static(id="status")
                yield Static(id="summary")
                yield Static("Discovered Devices", id="devices-title")
                yield DataTable(id="devices")
                yield Static("Selected Discovery", id="details-title")
                yield RichLog(
                    id="details-pane", markup=False, wrap=True, highlight=False
                )
            with Vertical(id="right-pane"):
                yield Static("Recent Discoveries", id="events-title")
                yield RichLog(id="events-log", markup=False, wrap=True, highlight=False)
        yield Footer()

    def on_mount(self) -> None:
        """Configure widgets and start the capture thread."""

        self.title = "Snoopy"
        self.sub_title = f"Passive recon on {self.interface}"

        table = self.query_one("#devices", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("Protocol", key="protocol", width=10)
        table.add_column("Identity", key="identity", width=28)
        table.add_column("Source IP", key="source_ip", width=20)
        table.add_column("Source MAC", key="source_mac", width=18)
        table.add_column("Location", key="location", width=22)
        table.add_column("Seen", key="seen_count", width=6)
        table.add_column("Last Seen", key="last_seen", width=10)
        table.add_column("Details", key="details", width=60)

        self.refresh_status()
        self.refresh_summary()
        self.refresh_details(None)

        self.capture_thread = threading.Thread(
            target=self.capture_loop,
            name="snoopy-capture",
            daemon=True,
        )
        self.capture_thread.start()
        self.set_interval(0.2, self.drain_messages)

    def on_unmount(self) -> None:
        """Stop capture when the app exits."""

        self.capture_session.stop()

    def action_toggle_log(self) -> None:
        """Show or hide the recent discoveries pane."""

        pane = self.query_one("#right-pane", Vertical)
        pane.styles.display = "block" if pane.styles.display == "none" else "none"

    def action_save_devices(self) -> None:
        """Save the discovered-device state to a JSON file in the current directory."""

        output_path = Path.cwd() / (
            f"snoopy-discoveries-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        )
        payload = {
            "generated_at": datetime.now().isoformat(),
            "interface": self.interface,
            "total_events": self.total_events,
            "unique_discoveries": len(self.records),
            "discoveries": [
                self.record_to_dict(record)
                for record in sorted(
                    self.records.values(),
                    key=lambda record: (record.last_seen, record.identity),
                    reverse=True,
                )
            ],
        }
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.status_message = (
            f"Saved {len(self.records)} discoveries to {output_path.name}"
        )
        self.refresh_status()

    def capture_loop(self) -> None:
        """Run the packet capture in a background thread."""

        try:
            for event in self.capture_session.iter_events():
                self.message_queue.put(ControlMessage(kind="event", payload=event))
            self.message_queue.put(ControlMessage(kind="stopped"))
        except SnoopyError as exc:
            self.message_queue.put(ControlMessage(kind="error", payload=str(exc)))

    def drain_messages(self) -> None:
        """Process queued capture messages and refresh the UI."""

        updated = False
        while True:
            try:
                message = self.message_queue.get_nowait()
            except queue.Empty:
                break

            if message.kind == "event":
                assert isinstance(message.payload, Event)
                updated = self.handle_event(message.payload) or updated
            elif message.kind == "error":
                error_text = str(message.payload)
                self.status_message = f"Capture failed: {error_text}"
                self.refresh_status()
                self.query_one("#events-log", RichLog).write(f"ERROR {error_text}")
                self.capture_session.stop()
            elif message.kind == "stopped":
                self.status_message = "Capture stopped."
                self.refresh_status()

        if updated:
            self.refresh_summary()
            self.refresh_table()

    def handle_event(self, event: Event) -> bool:
        """Update dashboard state from a newly observed event."""

        now = datetime.now()
        self.total_events += 1
        existing = self.records.get(event.dedupe_key)
        if existing is None:
            self.records[event.dedupe_key] = DiscoveryRecord(
                protocol=event.protocol,
                identity=event.identity,
                source_mac=event.source_mac,
                source_ip=event.source_ip,
                location=event.location,
                details=event.details,
                dedupe_key=event.dedupe_key,
                first_seen=now,
                last_seen=now,
                seen_count=1,
                summary=event.summary,
            )
            self.protocol_counts[event.protocol] += 1
            timestamp = now.strftime("%H:%M:%S")
            self.query_one("#events-log", RichLog).write(
                f"[{timestamp}] {event.summary}"
            )
            self.status_message = f"Listening on {self.interface} | unique={len(self.records)} | total={self.total_events}"
            self.refresh_status()
            return True

        self.records[event.dedupe_key] = DiscoveryRecord(
            protocol=existing.protocol,
            identity=existing.identity,
            source_mac=existing.source_mac,
            source_ip=event.source_ip or existing.source_ip,
            location=event.location or existing.location,
            details=event.details or existing.details,
            dedupe_key=existing.dedupe_key,
            first_seen=existing.first_seen,
            last_seen=now,
            seen_count=existing.seen_count + 1,
            summary=event.summary,
        )
        self.status_message = f"Listening on {self.interface} | unique={len(self.records)} | total={self.total_events}"
        self.refresh_status()
        return True

    def refresh_status(self) -> None:
        """Refresh the top status banner."""

        status_widget = self.query_one("#status", Static)
        tcpdump_path = require_tcpdump()
        status_widget.update(
            "\n".join(
                [
                    f"Interface: {self.interface}",
                    f"Backend: {tcpdump_path}",
                    self.status_message,
                ]
            )
        )

    def refresh_summary(self) -> None:
        """Refresh protocol counts and uptime."""

        summary_widget = self.query_one("#summary", Static)
        uptime = datetime.now() - self.started_at
        protocol_parts = (
            ", ".join(
                f"{protocol}={count}"
                for protocol, count in sorted(self.protocol_counts.items())
            )
            or "no discoveries yet"
        )
        summary_widget.update(
            "\n".join(
                [
                    f"Uptime: {str(uptime).split('.', maxsplit=1)[0]}",
                    f"Unique discoveries: {len(self.records)} | Total events: {self.total_events}",
                    f"Protocols: {protocol_parts}",
                    f"Sort: {self.COLUMN_LABELS[self.sort_column]} {'desc' if self.sort_reverse else 'asc'}",
                ]
            )
        )

    def refresh_table(self) -> None:
        """Rebuild the discovery table from current state."""

        table = self.query_one("#devices", DataTable)
        table.clear(columns=False)

        ordered_records = sorted(
            self.records.values(),
            key=self.record_sort_value,
            reverse=self.sort_reverse,
        )
        first_key: str | None = None

        for record in ordered_records:
            if first_key is None:
                first_key = record.dedupe_key
            table.add_row(
                record.protocol,
                record.identity,
                record.source_ip,
                record.source_mac,
                record.location,
                str(record.seen_count),
                record.last_seen.strftime("%H:%M:%S"),
                record.details,
                key=record.dedupe_key,
            )

        if table.row_count == 0:
            self.refresh_details(None)
            return

        selected_key = self.selected_record_key or first_key
        if selected_key not in self.records:
            selected_key = first_key

        if selected_key is not None:
            row_index = table.get_row_index(selected_key)
            table.move_cursor(row=row_index)
            self.selected_record_key = selected_key
            self.refresh_details(self.records[selected_key])

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        """Toggle sort direction when a column header is selected."""

        column_key = str(event.column_key.value)
        if column_key == self.sort_column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column_key
            self.sort_reverse = False
        self.refresh_summary()
        self.refresh_table()

    def record_sort_value(self, record: DiscoveryRecord) -> tuple[object, str]:
        """Return the active sort value for a discovery record."""

        value: object
        if self.sort_column == "protocol":
            value = record.protocol.casefold()
        elif self.sort_column == "identity":
            value = record.identity.casefold()
        elif self.sort_column == "source_ip":
            value = record.source_ip.casefold()
        elif self.sort_column == "source_mac":
            value = record.source_mac.casefold()
        elif self.sort_column == "location":
            value = record.location.casefold()
        elif self.sort_column == "seen_count":
            value = record.seen_count
        elif self.sort_column == "last_seen":
            value = record.last_seen
        elif self.sort_column == "details":
            value = record.details.casefold()
        else:
            value = record.last_seen
        return (value, record.identity.casefold())

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Update the detail pane when the highlighted row changes."""

        row_key = str(event.row_key.value) if event.row_key is not None else None
        self.selected_record_key = row_key
        record = self.records.get(row_key) if row_key is not None else None
        self.refresh_details(record)

    def refresh_details(self, record: DiscoveryRecord | None) -> None:
        """Render the full details for the selected discovery."""

        details_widget = self.query_one("#details-pane", RichLog)
        details_widget.clear()
        if record is None:
            details_widget.write("No discovery selected yet.")
            return

        details_widget.write(
            "\n".join(
                [
                    f"Protocol: {record.protocol}",
                    f"Identity: {record.identity}",
                    f"Source IP: {record.source_ip}",
                    f"Source MAC: {record.source_mac}",
                    f"Location: {record.location}",
                    f"First Seen: {record.first_seen.strftime('%Y-%m-%d %H:%M:%S')}",
                    f"Last Seen: {record.last_seen.strftime('%Y-%m-%d %H:%M:%S')}",
                    f"Seen Count: {record.seen_count}",
                    "",
                    "Details:",
                    record.details,
                    "",
                    "Summary:",
                    record.summary,
                ]
            ),
            scroll_end=False,
        )

    def record_to_dict(self, record: DiscoveryRecord) -> dict[str, str | int]:
        """Convert a discovery record to a JSON-serializable mapping."""

        return {
            "protocol": record.protocol,
            "identity": record.identity,
            "source_ip": record.source_ip,
            "source_mac": record.source_mac,
            "location": record.location,
            "details": record.details,
            "dedupe_key": record.dedupe_key,
            "first_seen": record.first_seen.isoformat(),
            "last_seen": record.last_seen.isoformat(),
            "seen_count": record.seen_count,
            "summary": record.summary,
        }


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line interface."""

    parser = argparse.ArgumentParser(
        description=(
            "Passively sniff CDP, LLDP, mDNS, and OSPF traffic on the local network."
        )
    )
    parser.add_argument(
        "-i",
        "--interface",
        help=(
            "Capture on a specific interface. Defaults to the system's default-route interface."
        ),
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        help="Stop after this many decoded discovery events.",
    )
    return parser


def require_tcpdump() -> str:
    """Return the tcpdump path or raise a helpful error."""

    tcpdump_path = shutil.which("tcpdump")
    if tcpdump_path is None:
        raise SnoopyError(
            "tcpdump was not found in PATH. Install tcpdump/libpcap and try again."
        )
    return tcpdump_path


def default_interface() -> str:
    """Detect the default-route interface for macOS or Linux."""

    if sys.platform == "darwin":
        return default_interface_macos()
    if sys.platform.startswith("linux"):
        return default_interface_linux()
    raise SnoopyError(
        f"Unsupported platform {sys.platform!r}. snoopy.py supports macOS and Linux."
    )


def default_interface_macos() -> str:
    """Detect the default interface on macOS."""

    commands = (
        ["route", "-n", "get", "default"],
        ["netstat", "-rn", "-f", "inet"],
    )
    for command in commands:
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError):
            continue

        interface_name = parse_macos_default_interface(command[0], result.stdout)
        if interface_name:
            return interface_name

    raise SnoopyError(
        "Unable to determine the default interface on macOS. Pass --interface explicitly."
    )


def parse_macos_default_interface(tool: str, output: str) -> str | None:
    """Parse default-route output from macOS route or netstat commands."""

    if tool == "route":
        for line in output.splitlines():
            if "interface:" in line:
                return line.split("interface:", maxsplit=1)[1].strip()
        return None

    candidates: list[str] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] != "default":
            continue
        interface_name = fields[-1]
        if interface_name.startswith("utun") or interface_name == "lo0":
            continue
        candidates.append(interface_name)

    if candidates:
        return candidates[0]
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "default":
            return fields[-1]
    return None


def default_interface_linux() -> str:
    """Detect the default interface on Linux."""

    commands = (
        ["ip", "route", "show", "default"],
        ["route", "-n"],
    )
    for command in commands:
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError):
            continue

        interface_name = parse_linux_default_interface(command[0], result.stdout)
        if interface_name:
            return interface_name

    raise SnoopyError(
        "Unable to determine the default interface on Linux. Pass --interface explicitly."
    )


def parse_linux_default_interface(tool: str, output: str) -> str | None:
    """Parse Linux default-route output from iproute2 or net-tools."""

    if tool == "ip":
        for line in output.splitlines():
            fields = line.split()
            if "dev" in fields:
                return fields[fields.index("dev") + 1]
        return None

    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0] == "0.0.0.0":
            return fields[-1]
    return None


def format_mac(raw: bytes) -> str:
    """Format a 6-byte MAC address."""

    return ":".join(f"{octet:02x}" for octet in raw)


def read_exact(stream: BinaryIO, size: int) -> bytes:
    """Read exactly size bytes from a stream."""

    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise EOFError("Unexpected end of pcap stream.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_pcap_header(stream: BinaryIO) -> PcapConfig:
    """Read the pcap global header and determine byte order."""

    header = read_exact(stream, 24)
    magic_le = struct.unpack("<I", header[:4])[0]
    if magic_le in (PCAP_MAGIC_USEC, PCAP_MAGIC_NSEC):
        return PcapConfig(endian="<")

    magic_be = struct.unpack(">I", header[:4])[0]
    if magic_be in (PCAP_MAGIC_USEC, PCAP_MAGIC_NSEC):
        return PcapConfig(endian=">")

    raise SnoopyError("tcpdump did not emit a recognizable pcap stream.")


def iter_pcap_packets(stream: BinaryIO) -> Iterator[bytes]:
    """Yield pcap packets from a stream until EOF."""

    config = read_pcap_header(stream)
    while True:
        header = stream.read(16)
        if not header:
            break
        if len(header) != 16:
            raise SnoopyError("Encountered a truncated pcap packet header.")

        _, _, captured_length, _ = struct.unpack(f"{config.endian}IIII", header)
        yield read_exact(stream, captured_length)


def extract_events(frame: bytes) -> list[Event]:
    """Decode all relevant events from one captured frame."""

    context, payload, protocol = parse_ethernet(frame)
    if protocol == ETH_P_LLDP:
        event = decode_lldp(context, payload)
        return [event] if event else []
    if protocol == ETH_P_IPV4:
        return decode_ipv4(context, payload)
    if protocol == ETH_P_IPV6:
        return decode_ipv6(context, payload)
    if protocol == -1:
        event = decode_cdp(context, payload)
        return [event] if event else []
    return []


def parse_ethernet(frame: bytes) -> tuple[PacketContext, bytes, int]:
    """Parse Ethernet framing, VLAN tags, and Cisco SNAP CDP frames."""

    if len(frame) < 14:
        raise SnoopyError("Captured frame is too short for Ethernet.")

    dst_mac = format_mac(frame[0:6])
    src_mac = format_mac(frame[6:12])
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14

    while ether_type in (ETH_P_8021Q, ETH_P_8021AD):
        if len(frame) < offset + 4:
            raise SnoopyError("Captured frame is truncated inside a VLAN tag.")
        ether_type = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        offset += 4

    context = PacketContext(src_mac=src_mac, dst_mac=dst_mac)

    if ether_type <= 1500:
        if len(frame) < offset + 8:
            raise SnoopyError("Captured 802.3 frame is too short for LLC SNAP.")
        dsap, ssap = frame[offset], frame[offset + 1]
        oui = frame[offset + 3 : offset + 6]
        pid = struct.unpack("!H", frame[offset + 6 : offset + 8])[0]
        if (
            dsap == LLC_SNAP_DSAP
            and ssap == LLC_SNAP_SSAP
            and oui == SNAP_CISCO_OUI
            and pid == SNAP_PID_CDP
        ):
            return context, frame[offset + 8 :], -1
        return context, b"", 0

    return context, frame[offset:], ether_type


def decode_lldp(context: PacketContext, payload: bytes) -> Event | None:
    """Decode LLDP TLVs into a structured event."""

    offset = 0
    fields: dict[str, str] = {}
    mgmt_addresses: list[str] = []

    while offset + 2 <= len(payload):
        tlv_header = struct.unpack("!H", payload[offset : offset + 2])[0]
        offset += 2
        tlv_type = (tlv_header >> 9) & 0x7F
        tlv_length = tlv_header & 0x1FF
        if offset + tlv_length > len(payload):
            break
        tlv_value = payload[offset : offset + tlv_length]
        offset += tlv_length

        if tlv_type == 0:
            break
        if tlv_type == 1:
            fields["chassis_id"] = decode_lldp_identifier(tlv_value)
        elif tlv_type == 2:
            fields["port_id"] = decode_lldp_identifier(tlv_value)
        elif tlv_type == 5:
            fields["system_name"] = safe_text(tlv_value)
        elif tlv_type == 6:
            fields["system_description"] = safe_text(tlv_value)
        elif tlv_type == 8:
            address = decode_lldp_management_address(tlv_value)
            if address:
                mgmt_addresses.append(address)

    if not fields and not mgmt_addresses:
        return None

    identity = fields.get("system_name") or fields.get("chassis_id") or context.src_mac
    location = fields.get("port_id") or context.dst_mac
    detail_parts = []
    if mgmt_addresses:
        detail_parts.append(f"mgmt={','.join(mgmt_addresses)}")
    if fields.get("system_description"):
        detail_parts.append(fields["system_description"])
    details = " | ".join(detail_parts) or "LLDP advertisement"

    summary_parts = [
        f"src_mac={context.src_mac}",
        f"identity={identity}",
        f"port={location}",
    ]
    if mgmt_addresses:
        summary_parts.append(f"management={','.join(mgmt_addresses)}")

    return Event(
        protocol="LLDP",
        summary="LLDP " + " ".join(summary_parts),
        dedupe_key=f"lldp:{identity}:{location}:{','.join(mgmt_addresses)}",
        identity=identity,
        source_mac=context.src_mac,
        source_ip=",".join(mgmt_addresses) or "n/a",
        location=location,
        details=details,
    )


def decode_lldp_identifier(value: bytes) -> str:
    """Decode an LLDP chassis-id or port-id TLV."""

    if not value:
        return ""
    subtype = value[0]
    body = value[1:]
    if subtype in {3, 4, 5, 7} and len(body) == 6:
        return format_mac(body)
    return safe_text(body)


def decode_lldp_management_address(value: bytes) -> str | None:
    """Decode an LLDP management-address TLV."""

    if len(value) < 2:
        return None
    addr_len = value[0]
    if len(value) < 1 + addr_len or addr_len < 2:
        return None
    addr_subtype = value[1]
    addr_value = value[2 : 1 + addr_len]
    if addr_subtype == 1 and len(addr_value) == 4:
        return str(ipaddress.IPv4Address(addr_value))
    if addr_subtype == 2 and len(addr_value) == 16:
        return str(ipaddress.IPv6Address(addr_value))
    return None


def decode_cdp(context: PacketContext, payload: bytes) -> Event | None:
    """Decode Cisco Discovery Protocol payloads."""

    if len(payload) < 4:
        return None

    offset = 4
    fields: dict[str, str] = {}
    addresses: list[str] = []

    while offset + 4 <= len(payload):
        tlv_type, tlv_length = struct.unpack("!HH", payload[offset : offset + 4])
        if tlv_length < 4 or offset + tlv_length > len(payload):
            break
        tlv_value = payload[offset + 4 : offset + tlv_length]
        offset += tlv_length

        if tlv_type == 0x0001:
            fields["device_id"] = safe_text(tlv_value)
        elif tlv_type == 0x0003:
            fields["port_id"] = safe_text(tlv_value)
        elif tlv_type == 0x0004:
            fields["capabilities"] = decode_cdp_capabilities(tlv_value)
        elif tlv_type == 0x0005:
            fields["software_version"] = safe_text(tlv_value)
        elif tlv_type == 0x0006:
            fields["platform"] = safe_text(tlv_value)
        elif tlv_type == 0x0002:
            addresses.extend(decode_cdp_addresses(tlv_value))

    if not fields and not addresses:
        return None

    identity = fields.get("device_id") or context.src_mac
    source_ip = ",".join(addresses) or "n/a"
    location = fields.get("port_id") or context.dst_mac
    detail_parts = [
        fields[key]
        for key in ("platform", "software_version", "capabilities")
        if fields.get(key)
    ]
    if addresses:
        detail_parts.append(f"addresses={','.join(addresses)}")
    details = " | ".join(detail_parts) or "CDP advertisement"

    return Event(
        protocol="CDP",
        summary=(
            f"CDP src_mac={context.src_mac} identity={identity} port={location} "
            f"addresses={source_ip}"
        ),
        dedupe_key=f"cdp:{identity}:{location}:{source_ip}",
        identity=identity,
        source_mac=context.src_mac,
        source_ip=source_ip,
        location=location,
        details=details,
    )


def decode_cdp_capabilities(value: bytes) -> str:
    """Decode the CDP capabilities bitmask."""

    if len(value) != 4:
        return safe_text(value)
    bits = struct.unpack("!I", value)[0]
    labels = (
        (0x01, "router"),
        (0x02, "transparent-bridge"),
        (0x04, "source-route-bridge"),
        (0x08, "switch"),
        (0x10, "host"),
        (0x20, "igmp"),
        (0x40, "repeater"),
    )
    enabled = [name for bit, name in labels if bits & bit]
    return ",".join(enabled) if enabled else str(bits)


def decode_cdp_addresses(value: bytes) -> list[str]:
    """Decode the CDP addresses TLV."""

    if len(value) < 4:
        return []
    count = struct.unpack("!I", value[:4])[0]
    offset = 4
    addresses: list[str] = []

    for _ in range(count):
        if offset + 2 > len(value):
            break
        protocol_type = value[offset]
        protocol_length = value[offset + 1]
        offset += 2
        if offset + protocol_length + 2 > len(value):
            break
        protocol = value[offset : offset + protocol_length]
        offset += protocol_length
        address_length = struct.unpack("!H", value[offset : offset + 2])[0]
        offset += 2
        if offset + address_length > len(value):
            break
        address_value = value[offset : offset + address_length]
        offset += address_length

        if protocol_type == 1 and protocol == b"\xcc" and address_length == 4:
            addresses.append(str(ipaddress.IPv4Address(address_value)))
        elif (
            protocol_type == 2
            and protocol == b"\xaa\xaa\x03\x00\x00\x00\x86\xdd"
            and address_length == 16
        ):
            addresses.append(str(ipaddress.IPv6Address(address_value)))
    return addresses


def decode_ipv4(context: PacketContext, payload: bytes) -> list[Event]:
    """Decode IPv4 discovery traffic."""

    if len(payload) < 20:
        return []
    version_ihl = payload[0]
    ihl = (version_ihl & 0x0F) * 4
    if len(payload) < ihl:
        return []

    src_ip = str(ipaddress.IPv4Address(payload[12:16]))
    dst_ip = str(ipaddress.IPv4Address(payload[16:20]))
    next_header = payload[9]
    next_payload = payload[ihl:]
    ip_context = PacketContext(
        src_mac=context.src_mac,
        dst_mac=context.dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )

    if next_header == 17:
        return decode_udp(ip_context, next_payload)
    if next_header == OSPF_PROTOCOL:
        event = decode_ospf(ip_context, next_payload)
        return [event] if event else []
    return []


def decode_ipv6(context: PacketContext, payload: bytes) -> list[Event]:
    """Decode IPv6 discovery traffic."""

    if len(payload) < 40:
        return []
    next_header = payload[6]
    src_ip = str(ipaddress.IPv6Address(payload[8:24]))
    dst_ip = str(ipaddress.IPv6Address(payload[24:40]))
    next_payload = payload[40:]
    ip_context = PacketContext(
        src_mac=context.src_mac,
        dst_mac=context.dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )

    if next_header == 17:
        return decode_udp(ip_context, next_payload)
    if next_header == OSPF_PROTOCOL:
        event = decode_ospfv3(ip_context, next_payload)
        return [event] if event else []
    return []


def decode_udp(context: PacketContext, payload: bytes) -> list[Event]:
    """Decode UDP payloads of interest."""

    if len(payload) < 8:
        return []
    src_port, dst_port, length, _ = struct.unpack("!HHHH", payload[:8])
    udp_payload = payload[8:length] if length >= 8 else payload[8:]
    if src_port == MDNS_PORT or dst_port == MDNS_PORT:
        event = decode_mdns(context, udp_payload)
        return [event] if event else []
    if src_port == NBNS_PORT or dst_port == NBNS_PORT:
        event = decode_nbns(context, udp_payload)
        return [event] if event else []
    if src_port == SSDP_PORT or dst_port == SSDP_PORT:
        event = decode_ssdp(context, udp_payload)
        return [event] if event else []
    if src_port == WSD_PORT or dst_port == WSD_PORT:
        event = decode_ws_discovery(context, udp_payload)
        return [event] if event else []
    return []


def decode_mdns(context: PacketContext, payload: bytes) -> Event | None:
    """Decode a minimal subset of mDNS/DNS messages."""

    if len(payload) < 12:
        return None
    _, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", payload[:12]
    )
    offset = 12
    names: list[str] = []
    addresses: list[str] = []

    try:
        for _ in range(qdcount):
            name, offset = decode_dns_name(payload, offset)
            if offset + 4 > len(payload):
                return None
            offset += 4
            names.append(name)

        for _ in range(ancount + nscount + arcount):
            name, offset = decode_dns_name(payload, offset)
            if offset + 10 > len(payload):
                return None
            rr_type, _, _, rdlength = struct.unpack(
                "!HHIH", payload[offset : offset + 10]
            )
            offset += 10
            if offset + rdlength > len(payload):
                return None
            rdata = payload[offset : offset + rdlength]
            offset += rdlength

            names.append(name)
            if rr_type == 1 and rdlength == 4:
                addresses.append(str(ipaddress.IPv4Address(rdata)))
            elif rr_type == 28 and rdlength == 16:
                addresses.append(str(ipaddress.IPv6Address(rdata)))
            elif rr_type in {12, 16, 33}:
                names.append(extract_dns_rdata_name(payload, rr_type, rdata))
    except (IndexError, ValueError):
        return None

    unique_names = dedupe_preserve(names)
    unique_addresses = dedupe_preserve(addresses)
    if not unique_names and not unique_addresses:
        return None

    qr = "response" if flags & 0x8000 else "query"
    identity = unique_names[0] if unique_names else context.src_ip or context.src_mac
    details = []
    if unique_names:
        details.append(f"names={','.join(unique_names[:6])}")
    if unique_addresses:
        details.append(f"addresses={','.join(unique_addresses[:6])}")

    return Event(
        protocol="mDNS",
        summary=(
            f"mDNS {qr} src_ip={context.src_ip} src_mac={context.src_mac} "
            f"identity={identity}"
        ),
        dedupe_key=f"mdns:{qr}:{identity}:{','.join(unique_addresses[:4])}",
        identity=identity,
        source_mac=context.src_mac,
        source_ip=context.src_ip or "n/a",
        location=qr,
        details=" | ".join(details) or "mDNS traffic",
    )


def decode_nbns(context: PacketContext, payload: bytes) -> Event | None:
    """Decode NetBIOS Name Service messages."""

    if len(payload) < 12:
        return None
    _, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", payload[:12]
    )
    offset = 12
    names: list[str] = []

    try:
        for _ in range(qdcount):
            encoded_name, offset = decode_dns_name(payload, offset)
            if offset + 4 > len(payload):
                return None
            offset += 4
            names.append(decode_netbios_name(encoded_name))

        for _ in range(ancount + nscount + arcount):
            encoded_name, offset = decode_dns_name(payload, offset)
            if offset + 10 > len(payload):
                return None
            _, _, _, rdlength = struct.unpack("!HHIH", payload[offset : offset + 10])
            offset += 10 + rdlength
            names.append(decode_netbios_name(encoded_name))
    except (IndexError, ValueError):
        return None

    decoded_names = [name for name in dedupe_preserve(names) if name]
    if not decoded_names:
        return None

    kind = "response" if flags & 0x8000 else "query"
    identity = decoded_names[0]
    return Event(
        protocol="NBNS",
        summary=(
            f"NBNS {kind} src_ip={context.src_ip} src_mac={context.src_mac} "
            f"identity={identity}"
        ),
        dedupe_key=f"nbns:{kind}:{identity}:{context.src_ip or context.src_mac}",
        identity=identity,
        source_mac=context.src_mac,
        source_ip=context.src_ip or "n/a",
        location=kind,
        details=f"names={','.join(decoded_names[:8])}",
    )


def decode_netbios_name(encoded_name: str) -> str:
    """Decode the first-level encoded NetBIOS name from NBNS."""

    label = encoded_name.split(".", maxsplit=1)[0]
    if len(label) != 32:
        return encoded_name

    decoded = bytearray()
    try:
        for index in range(0, 32, 2):
            high = ord(label[index]) - ord("A")
            low = ord(label[index + 1]) - ord("A")
            decoded.append((high << 4) | low)
    except ValueError:
        return encoded_name

    if len(decoded) != 16:
        return encoded_name
    base_name = decoded[:15].decode("ascii", errors="replace").rstrip(" ")
    suffix = decoded[15]
    return f"{base_name}<{suffix:02X}>"


def decode_ssdp(context: PacketContext, payload: bytes) -> Event | None:
    """Decode SSDP/UPnP discovery messages."""

    text = payload.decode("utf-8", errors="replace").strip()
    if not text:
        return None

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None

    start_line = lines[0]
    headers = parse_text_headers(lines[1:])
    message_type = start_line.split(" ", maxsplit=1)[0]
    identity = (
        headers.get("usn")
        or headers.get("location")
        or headers.get("server")
        or context.src_ip
        or context.src_mac
    )
    location = headers.get("nt") or headers.get("st") or message_type
    detail_parts = [
        f"{name}={value}"
        for name, value in (
            ("server", headers.get("server")),
            ("location", headers.get("location")),
            ("usn", headers.get("usn")),
            ("cache-control", headers.get("cache-control")),
        )
        if value
    ]

    return Event(
        protocol="SSDP",
        summary=(
            f"SSDP {message_type} src_ip={context.src_ip} src_mac={context.src_mac} "
            f"identity={identity}"
        ),
        dedupe_key=f"ssdp:{identity}:{location}:{context.src_ip or context.src_mac}",
        identity=identity,
        source_mac=context.src_mac,
        source_ip=context.src_ip or "n/a",
        location=location,
        details=" | ".join(detail_parts) or start_line,
    )


def decode_ws_discovery(context: PacketContext, payload: bytes) -> Event | None:
    """Decode WS-Discovery SOAP-over-UDP messages."""

    text = payload.decode("utf-8", errors="replace").strip()
    if not text:
        return None

    xml_start = text.find("<")
    if xml_start == -1:
        return None

    try:
        root = ET.fromstring(text[xml_start:])
    except ET.ParseError:
        return None

    action = find_xml_text(root, "Action") or "WS-Discovery"
    endpoint = find_xml_text(root, "Address")
    message_id = find_xml_text(root, "MessageID")
    types = find_xml_text(root, "Types")
    scopes = find_xml_text(root, "Scopes")
    xaddrs = find_xml_text(root, "XAddrs")

    action_name = action.rsplit("/", maxsplit=1)[-1]
    identity = endpoint or xaddrs or message_id or context.src_ip or context.src_mac
    detail_parts = [
        f"{name}={value}"
        for name, value in (
            ("types", types),
            ("scopes", scopes),
            ("xaddrs", xaddrs),
            ("message_id", message_id),
        )
        if value
    ]

    return Event(
        protocol="WS-Discovery",
        summary=(
            f"WS-Discovery {action_name} src_ip={context.src_ip} "
            f"src_mac={context.src_mac} identity={identity}"
        ),
        dedupe_key=(
            f"wsd:{action_name}:{identity}:{context.src_ip or context.src_mac}"
        ),
        identity=identity,
        source_mac=context.src_mac,
        source_ip=context.src_ip or "n/a",
        location=action_name,
        details=" | ".join(detail_parts) or action,
    )


def decode_dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name with compression support."""

    labels: list[str] = []
    jumped = False
    next_offset = offset
    visited: set[int] = set()

    while True:
        if offset >= len(payload):
            raise ValueError("DNS name exceeded payload bounds.")
        length = payload[offset]
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                raise ValueError("DNS compression pointer is truncated.")
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if pointer in visited:
                raise ValueError("DNS compression pointer loop detected.")
            visited.add(pointer)
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue

        offset += 1
        if offset + length > len(payload):
            raise ValueError("DNS label exceeds payload bounds.")
        labels.append(safe_text(payload[offset : offset + length]))
        offset += length
        if not jumped:
            next_offset = offset

    return ".".join(part for part in labels if part), next_offset


def extract_dns_rdata_name(payload: bytes, rr_type: int, rdata: bytes) -> str:
    """Extract a readable DNS RDATA name or text payload."""

    if rr_type == 16:
        parts: list[str] = []
        offset = 0
        while offset < len(rdata):
            length = rdata[offset]
            offset += 1
            parts.append(safe_text(rdata[offset : offset + length]))
            offset += length
        return ";".join(parts)

    if rr_type == 33:
        if len(rdata) < 6:
            return ""
        try:
            name, _ = decode_dns_name(payload, len(payload) - len(rdata) + 6)
            return name
        except ValueError:
            return ""

    try:
        name, _ = decode_dns_name(payload, len(payload) - len(rdata))
        return name
    except ValueError:
        return ""


def parse_text_headers(lines: list[str]) -> dict[str, str]:
    """Parse simple HTTP-style header lines into a normalized mapping."""

    headers: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        name, value = line.split(":", maxsplit=1)
        headers[name.strip().lower()] = value.strip()
    return headers


def find_xml_text(root: ET.Element, local_name: str) -> str | None:
    """Find the first XML element text matching a local tag name."""

    for element in root.iter():
        if element.tag.rsplit("}", maxsplit=1)[-1] == local_name:
            text = (element.text or "").strip()
            if text:
                return text
    return None


def decode_ospf(context: PacketContext, payload: bytes) -> Event | None:
    """Decode OSPFv2 packets."""

    if len(payload) < 24:
        return None
    version, packet_type, packet_length = struct.unpack("!BBH", payload[:4])
    if version != 2 or len(payload) < packet_length:
        return None
    router_id = str(ipaddress.IPv4Address(payload[4:8]))
    area_id = str(ipaddress.IPv4Address(payload[8:12]))
    packet_name = ospf_packet_type(packet_type)

    detail_parts = [f"area={area_id}", f"type={packet_name}"]
    if packet_type == 1 and packet_length >= 44:
        designated = str(ipaddress.IPv4Address(payload[36:40]))
        backup = str(ipaddress.IPv4Address(payload[40:44]))
        detail_parts.append(f"dr={designated}")
        detail_parts.append(f"bdr={backup}")

    return Event(
        protocol="OSPF",
        summary=(
            f"OSPF src_ip={context.src_ip} router_id={router_id} "
            f"area={area_id} type={packet_name}"
        ),
        dedupe_key=f"ospf:{router_id}:{area_id}:{packet_type}",
        identity=router_id,
        source_mac=context.src_mac,
        source_ip=context.src_ip or "n/a",
        location=area_id,
        details=" | ".join(detail_parts),
    )


def decode_ospfv3(context: PacketContext, payload: bytes) -> Event | None:
    """Decode OSPFv3 packets."""

    if len(payload) < 16:
        return None
    version, packet_type, packet_length = struct.unpack("!BBH", payload[:4])
    if version != 3 or len(payload) < packet_length:
        return None
    router_id = str(ipaddress.IPv4Address(payload[4:8]))
    area_id = str(ipaddress.IPv4Address(payload[8:12]))
    packet_name = ospf_packet_type(packet_type)

    return Event(
        protocol="OSPFv3",
        summary=(
            f"OSPFv3 src_ip={context.src_ip} router_id={router_id} "
            f"area={area_id} type={packet_name}"
        ),
        dedupe_key=f"ospfv3:{router_id}:{area_id}:{packet_type}",
        identity=router_id,
        source_mac=context.src_mac,
        source_ip=context.src_ip or "n/a",
        location=area_id,
        details=f"area={area_id} | type={packet_name}",
    )


def ospf_packet_type(packet_type: int) -> str:
    """Translate OSPF packet-type numbers."""

    return {
        1: "hello",
        2: "database-description",
        3: "link-state-request",
        4: "link-state-update",
        5: "link-state-ack",
    }.get(packet_type, str(packet_type))


def safe_text(value: bytes) -> str:
    """Decode bytes to readable text without raising."""

    return value.rstrip(b"\x00").decode("utf-8", errors="replace").strip()


def dedupe_preserve(values: list[str]) -> list[str]:
    """Remove duplicates without disturbing input order."""

    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output


def main() -> int:
    """Run the snoopy CLI."""

    parser = build_parser()
    args = parser.parse_args()

    if args.count is not None and args.count <= 0:
        parser.error("--count must be a positive integer.")

    try:
        require_tcpdump()
        interface = args.interface or default_interface()
    except SnoopyError as exc:
        parser.error(str(exc))

    app = SnoopyDashboard(interface=interface, count=args.count)
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
