#!/usr/bin/env -S uv run -q
# /// script
# requires-python = ">=3.13"
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

from textual import events
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, RichLog, Static

TCPDUMP_FILTER: Final[str] = (
    "(ether dst 01:00:0c:cc:cc:cc) or "
    "(ether proto 0x88cc) or "
    "(udp port 67) or "
    "(udp port 68) or "
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
DHCP_SERVER_PORT: Final[int] = 67
DHCP_CLIENT_PORT: Final[int] = 68
DHCP_FIXED_HEADER_LEN: Final[int] = 236
DHCP_MAGIC_COOKIE: Final[bytes] = b"\x63\x82\x53\x63"
DHCP_OPTION_END: Final[int] = 255
DHCP_OPTION_PAD: Final[int] = 0
DHCP_OPTION_HOSTNAME: Final[int] = 12
DHCP_OPTION_SUBNET_MASK: Final[int] = 1
DHCP_OPTION_ROUTER: Final[int] = 3
DHCP_OPTION_DNS_SERVERS: Final[int] = 6
DHCP_OPTION_DOMAIN_NAME: Final[int] = 15
DHCP_OPTION_NTP_SERVERS: Final[int] = 42
DHCP_OPTION_NETBIOS_NAME_SERVERS: Final[int] = 44
DHCP_OPTION_NETBIOS_NODE_TYPE: Final[int] = 46
DHCP_OPTION_MESSAGE_TYPE: Final[int] = 53
DHCP_OPTION_REQUESTED_IP: Final[int] = 50
DHCP_OPTION_LEASE_TIME: Final[int] = 51
DHCP_OPTION_SERVER_IDENTIFIER: Final[int] = 54
DHCP_OPTION_RENEWAL_TIME: Final[int] = 58
DHCP_OPTION_REBINDING_TIME: Final[int] = 59
DHCP_OPTION_TFTP_SERVER_NAME: Final[int] = 66
DHCP_OPTION_BOOTFILE_NAME: Final[int] = 67
DHCP_OPTION_DOMAIN_SEARCH: Final[int] = 119
DHCP_OPTION_CLASSLESS_STATIC_ROUTES: Final[int] = 121
DHCP_OPTION_MS_CLASSLESS_STATIC_ROUTES: Final[int] = 249
DHCP_MESSAGE_TYPES: Final[dict[int, str]] = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}
LLC_SNAP_DSAP: Final[int] = 0xAA
LLC_SNAP_SSAP: Final[int] = 0xAA
SNAP_CISCO_OUI: Final[bytes] = b"\x00\x00\x0c"
SNAP_PID_CDP: Final[int] = 0x2000
DEVICE_TABLE_FIXED_COLUMNS: Final[dict[str, int]] = {
    "protocol": 18,
    "identity": 28,
    "source_ip": 20,
    "source_mac": 18,
    "location": 22,
    "seen_count": 6,
    "last_seen": 10,
}
DEVICE_TABLE_DETAILS_MIN_WIDTH: Final[int] = 60


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
    destination_mac: str = ""
    destination_ip: str = ""


@dataclass(frozen=True)
class DiscoveryRecord:
    """Dashboard state for a unique discovery target."""

    protocol: str
    identity: str
    source_mac: str
    source_ip: str
    destination_mac: str
    destination_ip: str
    location: str
    details: str
    dedupe_key: str
    first_seen: datetime
    last_seen: datetime
    seen_count: int
    summary: str


@dataclass(frozen=True)
class DeviceRecord:
    """Aggregated view of likely observations from one physical device."""

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
    aliases: tuple[str, ...]
    observation_keys: tuple[str, ...]


@dataclass
class DeviceAggregate:
    """Mutable aggregate used while inferring physical devices."""

    records: list[DiscoveryRecord]
    aliases: set[str]
    identities: set[str]
    source_macs: set[str]
    source_ips: set[str]
    locations: list[str]
    protocols: Counter[str]


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
        "protocol": "Protocols",
        "identity": "Device",
        "source_ip": "Primary IP",
        "source_mac": "Primary MAC",
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
        self.devices: dict[str, DeviceRecord] = {}
        self.protocol_counts: Counter[str] = Counter()
        self.total_events = 0
        self.started_at = datetime.now()
        self.status_message = "Starting capture..."
        self.selected_record_key: str | None = None
        self.sort_column = "last_seen"
        self.sort_reverse = True
        self.details_column_key = "details"

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout."""

        yield Header(show_clock=True)
        with Horizontal(id="main"):
            with Vertical(id="left-pane"):
                yield Static(id="status")
                yield Static(id="summary")
                yield Static("Inferred Devices", id="devices-title")
                yield DataTable(id="devices")
                yield Static("Selected Device", id="details-title")
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
        table.add_column(
            "Protocols", key="protocol", width=DEVICE_TABLE_FIXED_COLUMNS["protocol"]
        )
        table.add_column("Device", key="identity", width=DEVICE_TABLE_FIXED_COLUMNS["identity"])
        table.add_column(
            "Primary IP", key="source_ip", width=DEVICE_TABLE_FIXED_COLUMNS["source_ip"]
        )
        table.add_column(
            "Primary MAC",
            key="source_mac",
            width=DEVICE_TABLE_FIXED_COLUMNS["source_mac"],
        )
        table.add_column(
            "Location", key="location", width=DEVICE_TABLE_FIXED_COLUMNS["location"]
        )
        table.add_column(
            "Seen", key="seen_count", width=DEVICE_TABLE_FIXED_COLUMNS["seen_count"]
        )
        table.add_column(
            "Last Seen",
            key="last_seen",
            width=DEVICE_TABLE_FIXED_COLUMNS["last_seen"],
        )
        self.details_column_key = table.add_column(
            "Details",
            key=self.details_column_key,
            width=DEVICE_TABLE_DETAILS_MIN_WIDTH,
        )
        self.resize_details_column()

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

    def on_resize(self, event: events.Resize) -> None:
        """Resize the details column to absorb remaining table width."""

        if self.is_mounted:
            self.resize_details_column()

    def resize_details_column(self) -> None:
        """Stretch the details column into any remaining table space."""

        table = self.query_one("#devices", DataTable)
        available_width = table.content_region.width or table.size.width
        if available_width <= 0 or self.details_column_key not in table.columns:
            return

        padding_width = 2 * table.cell_padding
        fixed_render_width = sum(
            width + padding_width for width in DEVICE_TABLE_FIXED_COLUMNS.values()
        )
        details_width = max(
            DEVICE_TABLE_DETAILS_MIN_WIDTH,
            available_width - fixed_render_width - padding_width,
        )
        column = table.columns[self.details_column_key]
        if column.width == details_width:
            return

        column.width = details_width
        table._require_update_dimensions = True
        table.check_idle()
        table.refresh(layout=True)

    def action_toggle_log(self) -> None:
        """Show or hide the recent discoveries pane."""

        pane = self.query_one("#right-pane", Vertical)
        pane.styles.display = "block" if pane.styles.display == "none" else "none"

    def action_save_devices(self) -> None:
        """Save the discovered-device state to a JSON file in the current directory."""

        self.refresh_devices()
        output_path = Path.cwd() / (
            f"snoopy-discoveries-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        )
        payload = {
            "generated_at": datetime.now().isoformat(),
            "interface": self.interface,
            "total_events": self.total_events,
            "unique_devices": len(self.devices),
            "raw_observations": len(self.records),
            "devices": [
                self.device_to_dict(record)
                for record in sorted(
                    self.devices.values(),
                    key=lambda record: (record.last_seen, record.identity),
                    reverse=True,
                )
            ],
        }
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.status_message = (
            f"Saved {len(self.devices)} devices to {output_path.name}"
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
            self.refresh_devices()
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
                destination_mac=event.destination_mac,
                destination_ip=event.destination_ip,
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
            destination_mac=event.destination_mac or existing.destination_mac,
            destination_ip=event.destination_ip or existing.destination_ip,
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

    def refresh_devices(self) -> None:
        """Rebuild inferred device state from the raw observation records."""

        self.devices = infer_devices(self.records)

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
                    f"Unique devices: {len(self.devices)} | Raw observations: {len(self.records)} | Total events: {self.total_events}",
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
            self.devices.values(),
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
        if selected_key not in self.devices:
            selected_key = first_key

        if selected_key is not None:
            row_index = table.get_row_index(selected_key)
            table.move_cursor(row=row_index)
            self.selected_record_key = selected_key
            self.refresh_details(self.devices[selected_key])

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

    def record_sort_value(self, record: DeviceRecord) -> tuple[object, str]:
        """Return the active sort value for an inferred device record."""

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
        device = self.devices.get(row_key) if row_key is not None else None
        self.refresh_details(device)

    def refresh_details(self, record: DeviceRecord | None) -> None:
        """Render the full details for the selected device."""

        details_widget = self.query_one("#details-pane", RichLog)
        details_widget.clear()
        if record is None:
            details_widget.write("No device selected yet.")
            return

        observations = [
            self.records[key]
            for key in record.observation_keys
            if key in self.records
        ]
        observations.sort(key=lambda item: (item.protocol, item.last_seen), reverse=True)
        observation_lines = self.format_protocol_sections(observations)

        lines = [
            f"Device: {record.identity}",
            f"Protocols: {record.protocol}",
            f"Primary IP: {record.source_ip}",
            f"Primary MAC: {record.source_mac}",
            f"Location: {record.location}",
            f"Aliases: {', '.join(record.aliases) or 'none'}",
            f"First Seen: {record.first_seen.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Last Seen: {record.last_seen.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Observation Count: {record.seen_count}",
            "",
            "Device Summary:",
            record.details,
            "",
            "Observations:",
            *observation_lines,
        ]
        details_widget.write("\n".join(lines), scroll_end=False)

    def format_protocol_sections(
        self, observations: list[DiscoveryRecord]
    ) -> list[str]:
        """Render observations grouped into distinct protocol sections."""

        sections: list[str] = []
        grouped: dict[str, list[DiscoveryRecord]] = {}
        for observation in observations:
            grouped.setdefault(observation.protocol, []).append(observation)

        for protocol in sorted(grouped):
            sections.append(f"[{protocol}]")
            for observation in sorted(
                grouped[protocol],
                key=lambda item: item.last_seen,
                reverse=True,
            ):
                sections.append(
                    f"  [{observation.last_seen.strftime('%H:%M:%S')}] "
                    f"id={observation.identity} src_ip={observation.source_ip} src_mac={observation.source_mac}"
                )
                extras: list[str] = [
                    f"location={observation.location}",
                    f"seen={observation.seen_count}",
                ]
                if observation.destination_ip:
                    extras.append(f"dst_ip={observation.destination_ip}")
                if observation.destination_mac:
                    extras.append(f"dst_mac={observation.destination_mac}")
                sections.append(f"    {' | '.join(extras)}")
                sections.append(f"    {observation.details}")
            sections.append("")

        while sections and not sections[-1]:
            sections.pop()
        return sections

    def device_to_dict(self, record: DeviceRecord) -> dict[str, str | int | list[str] | list[dict[str, str | int]]]:
        """Convert an inferred device record to a JSON-serializable mapping."""

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
            "aliases": list(record.aliases),
            "observations": [
                self.observation_to_dict(self.records[key])
                for key in record.observation_keys
                if key in self.records
            ],
        }

    def observation_to_dict(
        self, record: DiscoveryRecord
    ) -> dict[str, str | int]:
        """Convert a raw observation record to a JSON-serializable mapping."""

        return {
            "protocol": record.protocol,
            "identity": record.identity,
            "source_ip": record.source_ip,
            "source_mac": record.source_mac,
            "destination_ip": record.destination_ip,
            "destination_mac": record.destination_mac,
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
        destination_mac=context.dst_mac,
        destination_ip=context.dst_ip or "",
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
        destination_mac=context.dst_mac,
        destination_ip=context.dst_ip or "",
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
    if src_port in {DHCP_SERVER_PORT, DHCP_CLIENT_PORT} or dst_port in {
        DHCP_SERVER_PORT,
        DHCP_CLIENT_PORT,
    }:
        event = decode_dhcp(context, udp_payload)
        return [event] if event else []
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


def decode_dhcp(context: PacketContext, payload: bytes) -> Event | None:
    """Decode common DHCP messages while keeping the event stream compact."""

    if len(payload) < DHCP_FIXED_HEADER_LEN + len(DHCP_MAGIC_COOKIE):
        return None

    op = payload[0]
    hlen = payload[2]
    if op not in {1, 2} or hlen == 0 or hlen > 16:
        return None

    ciaddr = str(ipaddress.IPv4Address(payload[12:16]))
    yiaddr = str(ipaddress.IPv4Address(payload[16:20]))
    siaddr = str(ipaddress.IPv4Address(payload[20:24]))
    giaddr = str(ipaddress.IPv4Address(payload[24:28]))
    client_mac = format_mac(payload[28 : 28 + hlen])
    options_offset = DHCP_FIXED_HEADER_LEN
    if payload[options_offset : options_offset + 4] != DHCP_MAGIC_COOKIE:
        return None

    options = parse_dhcp_options(payload[options_offset + 4 :])
    message_type_value = options.get(DHCP_OPTION_MESSAGE_TYPE, b"")[:1]
    if not message_type_value:
        return None
    message_type = message_type_value[0]
    message_name = DHCP_MESSAGE_TYPES.get(message_type)
    if message_name is None:
        return None

    hostname = safe_text(options.get(DHCP_OPTION_HOSTNAME, b""))
    requested_ip = parse_dhcp_ipv4_option(options.get(DHCP_OPTION_REQUESTED_IP))
    server_identifier = parse_dhcp_ipv4_option(
        options.get(DHCP_OPTION_SERVER_IDENTIFIER)
    )
    relay = giaddr if giaddr != "0.0.0.0" else ""
    next_server = siaddr if siaddr != "0.0.0.0" else ""
    assigned_ip = yiaddr if yiaddr != "0.0.0.0" else ""

    if op == 2:
        identity = server_identifier or context.src_ip or context.src_mac
        source_ip = context.src_ip or server_identifier or "n/a"
        location = relay or next_server or (context.dst_ip or "broadcast")
        detail_parts = []
        if assigned_ip:
            detail_parts.append(f"offered_ip={assigned_ip}")
        if server_identifier:
            detail_parts.append(f"server_id={server_identifier}")
        if next_server:
            detail_parts.append(f"next_server={next_server}")
        if relay:
            detail_parts.append(f"relay={relay}")
        detail_parts.extend(format_dhcp_scope_options(options))
        if message_name == "offer":
            detail_parts.append(
                "visibility=reply traffic; passive visibility depends on capture vantage"
            )
        return Event(
            protocol="DHCP",
            summary=f"DHCP {message_name} server={identity}",
            dedupe_key=f"dhcp:server:{message_name}:{identity}:{relay or '-'}",
            identity=identity,
            source_mac=context.src_mac,
            source_ip=source_ip,
            location=location,
            details=" | ".join(detail_parts) or f"message_type={message_name}",
            destination_mac=context.dst_mac,
            destination_ip=context.dst_ip or "",
        )

    client_identity = hostname or client_mac or context.src_mac
    source_ip = ciaddr if ciaddr != "0.0.0.0" else (context.src_ip or "0.0.0.0")
    location = server_identifier or relay or (context.dst_ip or "broadcast")
    detail_parts = [f"client_mac={client_mac}"]
    if hostname:
        detail_parts.append(f"hostname={hostname}")
    if requested_ip:
        detail_parts.append(f"requested_ip={requested_ip}")
    if server_identifier:
        detail_parts.append(f"server_id={server_identifier}")
    if relay:
        detail_parts.append(f"relay={relay}")

    return Event(
        protocol="DHCP",
        summary=f"DHCP {message_name} client={client_identity}",
        dedupe_key=f"dhcp:client:{message_name}:{client_mac or client_identity}",
        identity=client_identity,
        source_mac=client_mac or context.src_mac,
        source_ip=source_ip,
        location=location,
        details=" | ".join(detail_parts),
        destination_mac=context.dst_mac,
        destination_ip=context.dst_ip or "",
    )


def parse_dhcp_options(payload: bytes) -> dict[int, bytes]:
    """Parse DHCP options into a simple code-to-value mapping."""

    options: dict[int, bytes] = {}
    offset = 0
    while offset < len(payload):
        code = payload[offset]
        offset += 1
        if code == DHCP_OPTION_PAD:
            continue
        if code == DHCP_OPTION_END:
            break
        if offset >= len(payload):
            break
        length = payload[offset]
        offset += 1
        if offset + length > len(payload):
            break
        options[code] = payload[offset : offset + length]
        offset += length
    return options


def parse_dhcp_ipv4_option(value: bytes | None) -> str | None:
    """Decode a 4-byte DHCP option payload as an IPv4 address."""

    if value is None or len(value) != 4:
        return None
    return str(ipaddress.IPv4Address(value))


def parse_dhcp_ipv4_list_option(value: bytes | None) -> list[str]:
    """Decode a DHCP option payload as a list of IPv4 addresses."""

    if value is None or len(value) == 0 or len(value) % 4 != 0:
        return []
    return [
        str(ipaddress.IPv4Address(value[offset : offset + 4]))
        for offset in range(0, len(value), 4)
    ]


def parse_dhcp_u32_option(value: bytes | None) -> int | None:
    """Decode a DHCP option payload as a big-endian unsigned integer."""

    if value is None or len(value) != 4:
        return None
    return struct.unpack("!I", value)[0]


def parse_dhcp_domain_search_option(value: bytes | None) -> list[str]:
    """Decode RFC 3397-style domain search data when it is uncompressed."""

    if not value:
        return []

    names: list[str] = []
    labels: list[str] = []
    offset = 0
    while offset < len(value):
        length = value[offset]
        offset += 1
        if length == 0:
            if labels:
                names.append(".".join(labels))
                labels = []
            continue
        if length & 0xC0:
            return []
        if offset + length > len(value):
            return []
        labels.append(safe_text(value[offset : offset + length]))
        offset += length

    if labels:
        names.append(".".join(labels))
    return names


def parse_dhcp_classless_routes_option(value: bytes | None) -> list[str]:
    """Decode DHCP classless static routes (options 121/249)."""

    if not value:
        return []

    routes: list[str] = []
    offset = 0
    while offset < len(value):
        prefix_length = value[offset]
        offset += 1
        destination_octets = (prefix_length + 7) // 8
        if offset + destination_octets + 4 > len(value):
            return []

        destination_bytes = value[offset : offset + destination_octets]
        offset += destination_octets
        destination = destination_bytes + b"\x00" * (4 - destination_octets)
        gateway = value[offset : offset + 4]
        offset += 4
        routes.append(
            f"{ipaddress.IPv4Address(destination)}/{prefix_length}->{ipaddress.IPv4Address(gateway)}"
        )
    return routes


def format_dhcp_scope_options(options: dict[int, bytes]) -> list[str]:
    """Render high-signal DHCP scope-style options for server replies."""

    detail_parts: list[str] = []

    subnet_mask = parse_dhcp_ipv4_option(options.get(DHCP_OPTION_SUBNET_MASK))
    if subnet_mask:
        detail_parts.append(f"mask={subnet_mask}")

    routers = parse_dhcp_ipv4_list_option(options.get(DHCP_OPTION_ROUTER))
    if routers:
        detail_parts.append(f"router={','.join(routers)}")

    dns_servers = parse_dhcp_ipv4_list_option(options.get(DHCP_OPTION_DNS_SERVERS))
    if dns_servers:
        detail_parts.append(f"dns={','.join(dns_servers)}")

    domain_name = safe_text(options.get(DHCP_OPTION_DOMAIN_NAME, b""))
    if domain_name:
        detail_parts.append(f"domain={domain_name}")

    domain_search = parse_dhcp_domain_search_option(
        options.get(DHCP_OPTION_DOMAIN_SEARCH)
    )
    if domain_search:
        detail_parts.append(f"search={','.join(domain_search)}")

    ntp_servers = parse_dhcp_ipv4_list_option(options.get(DHCP_OPTION_NTP_SERVERS))
    if ntp_servers:
        detail_parts.append(f"ntp={','.join(ntp_servers)}")

    netbios_servers = parse_dhcp_ipv4_list_option(
        options.get(DHCP_OPTION_NETBIOS_NAME_SERVERS)
    )
    if netbios_servers:
        detail_parts.append(f"netbios_ns={','.join(netbios_servers)}")

    netbios_node_type = options.get(DHCP_OPTION_NETBIOS_NODE_TYPE, b"")[:1]
    if netbios_node_type:
        detail_parts.append(f"netbios_node_type={netbios_node_type[0]}")

    lease_time = parse_dhcp_u32_option(options.get(DHCP_OPTION_LEASE_TIME))
    if lease_time is not None:
        detail_parts.append(f"lease={lease_time}s")

    renewal_time = parse_dhcp_u32_option(options.get(DHCP_OPTION_RENEWAL_TIME))
    if renewal_time is not None:
        detail_parts.append(f"t1={renewal_time}s")

    rebinding_time = parse_dhcp_u32_option(options.get(DHCP_OPTION_REBINDING_TIME))
    if rebinding_time is not None:
        detail_parts.append(f"t2={rebinding_time}s")

    tftp_server = safe_text(options.get(DHCP_OPTION_TFTP_SERVER_NAME, b""))
    if tftp_server:
        detail_parts.append(f"tftp={tftp_server}")

    bootfile = safe_text(options.get(DHCP_OPTION_BOOTFILE_NAME, b""))
    if bootfile:
        detail_parts.append(f"bootfile={bootfile}")

    routes = parse_dhcp_classless_routes_option(
        options.get(DHCP_OPTION_CLASSLESS_STATIC_ROUTES)
    )
    if routes:
        detail_parts.append(f"routes={';'.join(routes)}")

    ms_routes = parse_dhcp_classless_routes_option(
        options.get(DHCP_OPTION_MS_CLASSLESS_STATIC_ROUTES)
    )
    if ms_routes:
        detail_parts.append(f"ms_routes={';'.join(ms_routes)}")

    return detail_parts


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
        destination_mac=context.dst_mac,
        destination_ip=context.dst_ip or "",
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
        destination_mac=context.dst_mac,
        destination_ip=context.dst_ip or "",
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
        destination_mac=context.dst_mac,
        destination_ip=context.dst_ip or "",
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
        destination_mac=context.dst_mac,
        destination_ip=context.dst_ip or "",
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
        destination_mac=context.dst_mac,
        destination_ip=context.dst_ip or "",
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
        destination_mac=context.dst_mac,
        destination_ip=context.dst_ip or "",
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


def infer_devices(records: dict[str, DiscoveryRecord]) -> dict[str, DeviceRecord]:
    """Group raw observations into likely physical devices."""

    aggregates: list[DeviceAggregate | None] = []
    alias_to_index: dict[str, int] = {}

    for record in sorted(records.values(), key=lambda item: (item.first_seen, item.identity)):
        aliases = observation_aliases(record)
        matched_indexes = sorted(
            {alias_to_index[alias] for alias in aliases if alias in alias_to_index}
        )
        if matched_indexes:
            aggregate_index = matched_indexes[0]
            for other_index in matched_indexes[1:]:
                merge_device_aggregates(
                    aggregates, alias_to_index, aggregate_index, other_index
                )
        else:
            aggregate_index = len(aggregates)
            aggregates.append(
                DeviceAggregate(
                    records=[],
                    aliases=set(),
                    identities=set(),
                    source_macs=set(),
                    source_ips=set(),
                    locations=[],
                    protocols=Counter(),
                )
            )

        aggregate = aggregates[aggregate_index]
        assert aggregate is not None
        aggregate.records.append(record)
        aggregate.aliases.update(aliases)
        aggregate.protocols[record.protocol] += 1
        if useful_text(record.identity):
            aggregate.identities.add(record.identity)
        if is_mac_address(record.source_mac):
            aggregate.source_macs.add(record.source_mac.lower())
        for ip_value in split_observation_ips(record.source_ip):
            aggregate.source_ips.add(ip_value)
        if useful_text(record.location):
            aggregate.locations.append(record.location)
        for alias in aliases:
            alias_to_index[alias] = aggregate_index

    devices: dict[str, DeviceRecord] = {}
    for aggregate in aggregates:
        if aggregate is None or not aggregate.records:
            continue

        protocols = tuple(sorted(aggregate.protocols))
        identity = choose_device_identity(aggregate)
        primary_ip = choose_primary_ip(aggregate)
        primary_mac = choose_primary_mac(aggregate)
        location = choose_device_location(aggregate)
        aliases = tuple(sorted(display_alias(alias) for alias in aggregate.aliases))
        observation_keys = tuple(
            record.dedupe_key
            for record in sorted(
                aggregate.records,
                key=lambda item: (item.last_seen, item.protocol, item.identity),
                reverse=True,
            )
        )
        details = summarize_device(aggregate)
        device_key = choose_device_key(aggregate, identity, primary_ip, primary_mac)
        first_seen = min(record.first_seen for record in aggregate.records)
        last_seen = max(record.last_seen for record in aggregate.records)
        seen_count = sum(record.seen_count for record in aggregate.records)

        devices[device_key] = DeviceRecord(
            protocol=",".join(protocols),
            identity=identity,
            source_mac=primary_mac,
            source_ip=primary_ip,
            location=location,
            details=details,
            dedupe_key=device_key,
            first_seen=first_seen,
            last_seen=last_seen,
            seen_count=seen_count,
            summary=f"{identity} via {', '.join(protocols)}",
            aliases=aliases,
            observation_keys=observation_keys,
        )

    return devices


def merge_device_aggregates(
    aggregates: list[DeviceAggregate | None],
    alias_to_index: dict[str, int],
    target_index: int,
    source_index: int,
) -> None:
    """Merge one in-progress device aggregate into another."""

    if source_index == target_index:
        return
    source = aggregates[source_index]
    target = aggregates[target_index]
    if source is None or target is None:
        return

    target.records.extend(source.records)
    target.aliases.update(source.aliases)
    target.identities.update(source.identities)
    target.source_macs.update(source.source_macs)
    target.source_ips.update(source.source_ips)
    target.locations.extend(source.locations)
    target.protocols.update(source.protocols)
    for alias in source.aliases:
        alias_to_index[alias] = target_index
    aggregates[source_index] = None


def observation_aliases(record: DiscoveryRecord) -> set[str]:
    """Extract identity aliases from a raw observation."""

    aliases: set[str] = set()
    if is_mac_address(record.source_mac):
        aliases.add(f"mac:{record.source_mac.lower()}")

    for ip_value in split_observation_ips(record.source_ip):
        aliases.add(f"ip:{ip_value}")

    identity = record.identity.strip()
    if not identity:
        return aliases
    if is_mac_address(identity):
        aliases.add(f"mac:{identity.lower()}")
    elif is_ip_address(identity):
        aliases.add(f"ip:{identity}")
    elif useful_text(identity):
        aliases.add(f"id:{identity.casefold()}")
    return aliases


def split_observation_ips(value: str) -> list[str]:
    """Split a possibly comma-delimited source IP field into usable IPs."""

    parts = [part.strip() for part in value.split(",")]
    return [
        part
        for part in parts
        if part and part != "n/a" and is_ip_address(part)
    ]


def choose_device_identity(aggregate: DeviceAggregate) -> str:
    """Choose the most human-friendly label for an inferred device."""

    scored_candidates: list[tuple[int, datetime, str]] = []
    for record in aggregate.records:
        candidate = record.identity.strip()
        if not useful_text(candidate):
            continue
        scored_candidates.append(
            (device_identity_score(record.protocol, candidate), record.last_seen, candidate)
        )
    if scored_candidates:
        return max(scored_candidates)[2]
    primary_ip = choose_primary_ip(aggregate)
    if primary_ip != "n/a":
        return primary_ip
    primary_mac = choose_primary_mac(aggregate)
    if primary_mac != "n/a":
        return primary_mac
    return "unknown-device"


def device_identity_score(protocol: str, value: str) -> int:
    """Score identity candidates for device-centric presentation."""

    score = {
        "LLDP": 100,
        "CDP": 95,
        "NBNS": 80,
        "mDNS": 70,
        "DHCP": 65,
        "WS-Discovery": 60,
        "SSDP": 50,
        "OSPF": 40,
        "OSPFv3": 40,
    }.get(protocol, 50)
    lowered = value.casefold()
    if ".local" in lowered or lowered.endswith(".lan"):
        score += 8
    if any(marker in lowered for marker in ("uuid:", "urn:", "upnp", "_tcp", "_udp")):
        score -= 20
    if "<" in value and ">" in value:
        score -= 10
    if is_ip_address(value) or is_mac_address(value):
        score -= 25
    return score


def choose_primary_ip(aggregate: DeviceAggregate) -> str:
    """Pick the most useful IP address for an inferred device."""

    if not aggregate.source_ips:
        return "n/a"
    return max(aggregate.source_ips, key=ip_preference)


def ip_preference(value: str) -> tuple[int, str]:
    """Rank IPs for display preference."""

    address = ipaddress.ip_address(value)
    if address.is_private and not address.is_link_local:
        rank = 4
    elif address.is_global:
        rank = 3
    elif address.is_link_local:
        rank = 2
    else:
        rank = 1
    return (rank, value)


def choose_primary_mac(aggregate: DeviceAggregate) -> str:
    """Pick the best representative MAC address for an inferred device."""

    if not aggregate.source_macs:
        return "n/a"
    return sorted(aggregate.source_macs)[0]


def choose_device_location(aggregate: DeviceAggregate) -> str:
    """Choose a representative location string for an inferred device."""

    if not aggregate.locations:
        return "n/a"
    scores = [
        (
            device_location_score(location),
            aggregate.locations.count(location),
            location,
        )
        for location in set(aggregate.locations)
    ]
    return max(scores)[2]


def device_location_score(location: str) -> int:
    """Score location strings, preferring switch-port style values."""

    lowered = location.casefold()
    if any(token in lowered for token in ("gi", "fa", "te", "ethernet", "port")):
        return 3
    if lowered in {"query", "response", "broadcast"}:
        return 1
    return 2


def summarize_device(aggregate: DeviceAggregate) -> str:
    """Create a compact table summary for an inferred device."""

    parts = [f"signals={','.join(sorted(aggregate.protocols))}"]
    identities = [
        identity
        for identity in sorted(aggregate.identities)
        if identity != choose_primary_mac(aggregate)
    ]
    if identities:
        parts.append(f"ids={','.join(identities[:3])}")
    if aggregate.source_ips:
        parts.append(f"ips={','.join(sorted(aggregate.source_ips)[:3])}")
    return " | ".join(parts)


def choose_device_key(
    aggregate: DeviceAggregate,
    identity: str,
    primary_ip: str,
    primary_mac: str,
) -> str:
    """Create a stable selection key for an inferred device."""

    if useful_text(identity) and not is_ip_address(identity) and not is_mac_address(identity):
        return f"device:id:{identity.casefold()}"
    if primary_ip != "n/a":
        return f"device:ip:{primary_ip}"
    if primary_mac != "n/a":
        return f"device:mac:{primary_mac}"
    return f"device:obs:{aggregate.records[0].dedupe_key}"


def display_alias(alias: str) -> str:
    """Convert an internal alias token into human-readable text."""

    _, value = alias.split(":", maxsplit=1)
    return value


def useful_text(value: str) -> bool:
    """Return whether a string contains a meaningful, displayable value."""

    return bool(value and value.strip() and value.strip() != "n/a")


def is_ip_address(value: str) -> bool:
    """Return whether the given string is an IP address."""

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_mac_address(value: str) -> bool:
    """Return whether the given string looks like a MAC address."""

    parts = value.split(":")
    return len(parts) == 6 and all(len(part) == 2 for part in parts)


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
