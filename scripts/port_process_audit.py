#!/usr/bin/env python3
"""Audit local ports, processes, and external connections on Linux.

This is a triage tool, not a malware detector. It reads Linux /proc socket and
process metadata, then flags patterns that commonly deserve human review:

* established TCP connections to public IP addresses
* listeners exposed on all interfaces
* socket-owning processes running from temporary or writable locations
* deleted executables that still have live network sockets

Run with root privileges for the most complete process-to-socket mapping.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import pwd
import re
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PROC_ROOT = Path("/proc")

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

UDP_STATES = {
    "07": "UNCONN",
}

COMMON_SERVICE_PORTS = {
    20,
    21,
    22,
    25,
    53,
    67,
    68,
    80,
    110,
    123,
    143,
    443,
    465,
    587,
    993,
    995,
}

RISKY_EXPOSED_PORTS = {
    23: "Telnet",
    2323: "alternate Telnet",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    3306: "MySQL",
    5432: "PostgreSQL",
}

ODD_REMOTE_PORTS = {
    1337,
    4444,
    5555,
    6666,
    6667,
    9001,
    9050,
    31337,
}

SUSPICIOUS_PROCESS_NAMES = {
    "kinsing",
    "kdevtmpfsi",
    "xmrig",
    "minerd",
    "masscan",
    "pnscan",
    "tsm",
    "watchbog",
}

WRITABLE_EXEC_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/user/",
)

SEVERITY_SCORE = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}


@dataclass(frozen=True)
class Endpoint:
    address: str
    port: int

    def as_text(self) -> str:
        if ":" in self.address and not self.address.startswith("::ffff:"):
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        return {"address": self.address, "port": self.port}


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int | None
    uid: int | None
    user: str
    name: str
    cmdline: str
    exe: str
    cwd: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "uid": self.uid,
            "user": self.user,
            "name": self.name,
            "cmdline": self.cmdline,
            "exe": self.exe,
            "cwd": self.cwd,
        }


@dataclass(frozen=True)
class SocketRecord:
    protocol: str
    family: str
    local: Endpoint
    remote: Endpoint
    state: str
    uid: int | None
    inode: str
    processes: tuple[ProcessInfo, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "family": self.family,
            "local": self.local.to_dict(),
            "remote": self.remote.to_dict(),
            "state": self.state,
            "uid": self.uid,
            "inode": self.inode,
            "processes": [process.to_dict() for process in self.processes],
        }


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    reasons: tuple[str, ...]
    socket: SocketRecord
    process: ProcessInfo | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "reasons": list(self.reasons),
            "socket": self.socket.to_dict(),
            "process": self.process.to_dict() if self.process else None,
        }


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return ""


def read_link(path: Path) -> str:
    try:
        return os.readlink(path)
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return ""


def decode_ipv4(hex_address: str) -> str:
    raw = bytes.fromhex(hex_address)
    return socket.inet_ntop(socket.AF_INET, raw[::-1])


def decode_ipv6(hex_address: str) -> str:
    raw = bytes.fromhex(hex_address)
    # /proc/net/tcp6 stores IPv6 addresses as little-endian 32-bit words.
    packed = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, packed)


def parse_endpoint(value: str, family: str) -> Endpoint:
    address_hex, port_hex = value.split(":")
    if family == "ipv4":
        address = decode_ipv4(address_hex)
    else:
        address = decode_ipv6(address_hex)
    return Endpoint(address=address, port=int(port_hex, 16))


def parse_socket_table(path: Path, protocol: str, family: str) -> list[SocketRecord]:
    records: list[SocketRecord] = []
    state_map = TCP_STATES if protocol == "tcp" else UDP_STATES

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (FileNotFoundError, PermissionError):
        return records

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue

        try:
            local = parse_endpoint(parts[1], family)
            remote = parse_endpoint(parts[2], family)
            state = state_map.get(parts[3], parts[3])
            uid = int(parts[7])
            inode = parts[9]
        except (IndexError, ValueError, OSError):
            continue

        records.append(
            SocketRecord(
                protocol=protocol,
                family=family,
                local=local,
                remote=remote,
                state=state,
                uid=uid,
                inode=inode,
                processes=(),
            )
        )

    return records


def collect_sockets(include_udp: bool) -> list[SocketRecord]:
    tables = [
        ("tcp", "ipv4", PROC_ROOT / "net" / "tcp"),
        ("tcp", "ipv6", PROC_ROOT / "net" / "tcp6"),
    ]
    if include_udp:
        tables.extend(
            [
                ("udp", "ipv4", PROC_ROOT / "net" / "udp"),
                ("udp", "ipv6", PROC_ROOT / "net" / "udp6"),
            ]
        )

    records: list[SocketRecord] = []
    for protocol, family, path in tables:
        records.extend(parse_socket_table(path, protocol, family))
    return records


def process_ids() -> Iterable[int]:
    for entry in PROC_ROOT.iterdir():
        if entry.name.isdigit():
            yield int(entry.name)


def parse_status(pid: int) -> tuple[int | None, int | None]:
    uid = None
    ppid = None
    for line in read_text(PROC_ROOT / str(pid) / "status").splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                uid = int(parts[1])
        elif line.startswith("PPid:"):
            parts = line.split()
            if len(parts) >= 2:
                ppid = int(parts[1])
    return uid, ppid


def user_from_uid(uid: int | None) -> str:
    if uid is None:
        return "unknown"
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def read_cmdline(pid: int) -> str:
    try:
        raw = (PROC_ROOT / str(pid) / "cmdline").read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()


def get_process_info(pid: int) -> ProcessInfo:
    uid, ppid = parse_status(pid)
    name = read_text(PROC_ROOT / str(pid) / "comm") or f"pid-{pid}"
    cmdline = read_cmdline(pid)
    exe = read_link(PROC_ROOT / str(pid) / "exe")
    cwd = read_link(PROC_ROOT / str(pid) / "cwd")
    return ProcessInfo(
        pid=pid,
        ppid=ppid,
        uid=uid,
        user=user_from_uid(uid),
        name=name,
        cmdline=cmdline,
        exe=exe,
        cwd=cwd,
    )


def build_inode_process_map() -> dict[str, list[int]]:
    inode_to_pids: dict[str, list[int]] = {}
    socket_pattern = re.compile(r"^socket:\[(\d+)\]$")

    for pid in process_ids():
        fd_dir = PROC_ROOT / str(pid) / "fd"
        try:
            descriptors = list(fd_dir.iterdir())
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue

        for descriptor in descriptors:
            target = read_link(descriptor)
            match = socket_pattern.match(target)
            if not match:
                continue
            inode_to_pids.setdefault(match.group(1), []).append(pid)

    return inode_to_pids


def attach_processes(records: list[SocketRecord]) -> list[SocketRecord]:
    inode_to_pids = build_inode_process_map()
    process_cache: dict[int, ProcessInfo] = {}
    attached: list[SocketRecord] = []

    for record in records:
        processes = []
        for pid in sorted(set(inode_to_pids.get(record.inode, []))):
            if pid not in process_cache:
                process_cache[pid] = get_process_info(pid)
            processes.append(process_cache[pid])

        attached.append(
            SocketRecord(
                protocol=record.protocol,
                family=record.family,
                local=record.local,
                remote=record.remote,
                state=record.state,
                uid=record.uid,
                inode=record.inode,
                processes=tuple(processes),
            )
        )

    return attached


def ip_class(address: str) -> str:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"

    if parsed.is_unspecified:
        return "wildcard"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link-local"
    if parsed.is_private:
        return "private"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_global:
        return "public"
    return "reserved"


def is_listener(record: SocketRecord) -> bool:
    if record.protocol == "tcp":
        return record.state == "LISTEN"
    return record.protocol == "udp" and record.local.port != 0 and record.remote.port == 0


def is_established_public_connection(record: SocketRecord, include_local: bool) -> bool:
    if record.protocol != "tcp" or record.state != "ESTABLISHED" or record.remote.port == 0:
        return False
    if include_local:
        return True
    return ip_class(record.remote.address) == "public"


def is_wildcard_listener(record: SocketRecord) -> bool:
    return is_listener(record) and ip_class(record.local.address) == "wildcard"


def has_deleted_exe(process: ProcessInfo | None) -> bool:
    return bool(process and process.exe.endswith(" (deleted)"))


def has_writable_exe(process: ProcessInfo | None) -> bool:
    if not process or not process.exe:
        return False
    exe = process.exe.removesuffix(" (deleted)")
    return exe.startswith(WRITABLE_EXEC_PREFIXES)


def suspicious_process_name(process: ProcessInfo | None) -> bool:
    return bool(process and process.name.lower() in SUSPICIOUS_PROCESS_NAMES)


def choose_severity(reasons: list[tuple[str, str]]) -> str:
    severity = "info"
    for candidate, _ in reasons:
        if SEVERITY_SCORE[candidate] > SEVERITY_SCORE[severity]:
            severity = candidate
    return severity


def process_label(process: ProcessInfo | None) -> str:
    if not process:
        return "unknown process"
    return f"{process.name} pid={process.pid} user={process.user}"


def analyze_record(record: SocketRecord, include_local: bool) -> list[Finding]:
    processes: tuple[ProcessInfo | None, ...] = record.processes or (None,)
    findings: list[Finding] = []

    for process in processes:
        reasons: list[tuple[str, str]] = []
        title = ""

        if is_established_public_connection(record, include_local):
            remote_class = ip_class(record.remote.address)
            title = "Established external TCP connection"
            if record.remote.port in ODD_REMOTE_PORTS:
                reasons.append(
                    (
                        "medium",
                        f"remote port {record.remote.port} is often used by backdoors, proxies, or tunneling tools",
                    )
                )
            elif record.remote.port not in COMMON_SERVICE_PORTS:
                reasons.append(
                    (
                        "low",
                        f"remote {remote_class} port {record.remote.port} is not in the common service port list",
                    )
                )
            else:
                reasons.append(("info", f"remote address is {remote_class}"))

        if is_wildcard_listener(record):
            exposed_port = RISKY_EXPOSED_PORTS.get(record.local.port)
            title = "Network listener exposed on all interfaces"
            if exposed_port:
                reasons.append(("medium", f"{exposed_port} is listening on all interfaces"))
            elif record.local.port not in COMMON_SERVICE_PORTS:
                reasons.append(
                    (
                        "low",
                        f"port {record.local.port} is listening on all interfaces and is not a common service port",
                    )
                )
            else:
                reasons.append(("info", f"common service port {record.local.port} is listening on all interfaces"))

        if has_deleted_exe(process):
            title = title or "Socket owned by a deleted executable"
            reasons.append(("high", "process executable has been deleted while the process is still running"))

        if has_writable_exe(process):
            title = title or "Socket owned by executable in writable path"
            reasons.append(("high", f"process executable is under a writable location: {process.exe}"))

        if suspicious_process_name(process):
            title = title or "Socket owned by suspicious process name"
            reasons.append(("medium", f"process name matches a known suspicious/miner pattern: {process.name}"))

        if reasons:
            findings.append(
                Finding(
                    severity=choose_severity(reasons),
                    title=title or "Network activity needs review",
                    reasons=tuple(reason for _, reason in reasons),
                    socket=record,
                    process=process,
                )
            )

    return findings


def analyze(records: list[SocketRecord], include_local: bool) -> list[Finding]:
    findings: list[Finding] = []
    for record in records:
        findings.extend(analyze_record(record, include_local=include_local))
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_SCORE[finding.severity],
            finding.socket.protocol,
            finding.socket.local.port,
            finding.socket.remote.port,
            process_label(finding.process),
        ),
    )


def summarize_counts(records: list[SocketRecord], findings: list[Finding]) -> dict[str, Any]:
    listener_count = sum(1 for record in records if is_listener(record))
    established_count = sum(1 for record in records if record.protocol == "tcp" and record.state == "ESTABLISHED")
    process_ids_with_sockets = {
        process.pid
        for record in records
        for process in record.processes
    }
    finding_counts: dict[str, int] = {severity: 0 for severity in SEVERITY_SCORE}
    for finding in findings:
        finding_counts[finding.severity] += 1
    return {
        "sockets": len(records),
        "listeners": listener_count,
        "established_tcp": established_count,
        "processes_with_sockets": len(process_ids_with_sockets),
        "findings_by_severity": finding_counts,
    }


def format_socket(record: SocketRecord) -> str:
    return (
        f"{record.protocol.upper()}/{record.family} {record.state} "
        f"{record.local.as_text()} -> {record.remote.as_text()}"
    )


def print_human_report(
    records: list[SocketRecord],
    findings: list[Finding],
    show_all: bool,
    max_findings: int,
) -> None:
    counts = summarize_counts(records, findings)
    print("Local port/process security audit")
    print(f"Scanned at: {dt.datetime.now(dt.timezone.utc).isoformat()}")
    print(
        "Summary: "
        f"{counts['sockets']} sockets, "
        f"{counts['listeners']} listeners, "
        f"{counts['established_tcp']} established TCP connections, "
        f"{counts['processes_with_sockets']} processes with sockets"
    )
    print(
        "Findings: "
        + ", ".join(
            f"{severity}={counts['findings_by_severity'][severity]}"
            for severity in ("high", "medium", "low", "info")
        )
    )
    if os.geteuid() != 0:
        print("Note: run with sudo/root for the most complete process ownership details.")

    print()
    if not findings:
        print("No heuristic findings were identified. This does not prove the host is malware-free.")
    else:
        print("Heuristic findings:")
        for index, finding in enumerate(findings[:max_findings], start=1):
            process = finding.process
            print(f"{index}. [{finding.severity.upper()}] {finding.title}")
            print(f"   Socket: {format_socket(finding.socket)}")
            print(f"   Process: {process_label(process)}")
            if process and process.exe:
                print(f"   Executable: {process.exe}")
            if process and process.cmdline:
                print(f"   Command: {process.cmdline}")
            for reason in finding.reasons:
                print(f"   - {reason}")
        if len(findings) > max_findings:
            print(f"... truncated {len(findings) - max_findings} additional findings")

    if show_all:
        print()
        print("All sockets:")
        for record in records:
            processes = ", ".join(process_label(process) for process in record.processes) or "unknown process"
            print(f"- {format_socket(record)} ({processes})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scan Linux /proc for listening ports, socket-owning processes, "
            "and suspicious external TCP connections."
        )
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of a human report",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="include every observed socket in the output",
    )
    parser.add_argument(
        "--include-local",
        action="store_true",
        help="treat loopback/private established TCP connections as reviewable too",
    )
    parser.add_argument(
        "--no-udp",
        action="store_true",
        help="skip UDP socket tables",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=50,
        help="maximum findings to print in human output (default: 50)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "high", "medium", "low", "info"),
        default="none",
        help="exit with status 1 if any finding meets this severity threshold",
    )
    return parser


def should_fail(findings: list[Finding], threshold: str) -> bool:
    if threshold == "none":
        return False
    threshold_score = SEVERITY_SCORE[threshold]
    return any(SEVERITY_SCORE[finding.severity] >= threshold_score for finding in findings)


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    records = attach_processes(collect_sockets(include_udp=not args.no_udp))
    findings = analyze(records, include_local=args.include_local)
    counts = summarize_counts(records, findings)

    if args.json:
        payload: dict[str, Any] = {
            "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "note": "Heuristic triage only; this does not prove malware presence or absence.",
            "counts": counts,
            "findings": [finding.to_dict() for finding in findings],
        }
        if args.show_all:
            payload["sockets"] = [record.to_dict() for record in records]
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print_human_report(
            records=records,
            findings=findings,
            show_all=args.show_all,
            max_findings=max(args.max_findings, 0),
        )

    return 1 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
