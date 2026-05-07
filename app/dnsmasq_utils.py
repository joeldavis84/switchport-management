import os
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from netmiko import ConnectHandler


DNSMASQ_HOST = "192.168.27.12"
DNSMASQ_USER = "root"

# Keep snapshots inside the container filesystem.
DNSMASQ_SNAPSHOT_ROOT = "/tmp/dnsmasq_snapshot"


@dataclass(frozen=True)
class DnsmasqSnapshot:
    snapshot_dir: str
    files: List[str]  # relative paths


def _linux_connection(host: str, username: str):
    # Use the same SSH key path pattern as the switch utilities.
    return ConnectHandler(
        device_type="linux",
        host=host,
        username=username,
        use_keys=True,
        key_file="/root/.ssh/id_rsa",
        allow_agent=True,
    )


def _safe_relpath(p: str) -> Optional[str]:
    p = (p or "").strip()
    if not p:
        return None
    if p.startswith("/"):
        p = p[1:]
    if ".." in p:
        return None
    return p


def _write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text if text is not None else "")


def _parse_dnsmasq_lines(text: str) -> List[str]:
    """
    Minimal, read-only parser: returns non-empty, non-comment config lines.
    """
    out: List[str] = []
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith("#") or s.startswith(";"):
            continue
        out.append(s)
    return out


def snapshot_dnsmasq_configs() -> Tuple[Optional[DnsmasqSnapshot], Optional[str]]:
    """
    Fetch /etc/dnsmasq.conf and all /etc/dnsmasq.d/* files from the remote host,
    store them locally in the container, and return the snapshot metadata.
    """
    snap_id = time.strftime("%Y%m%d-%H%M%S")
    snap_dir = os.path.join(DNSMASQ_SNAPSHOT_ROOT, snap_id)
    os.makedirs(snap_dir, exist_ok=True)

    rel_files: List[str] = []
    try:
        with _linux_connection(DNSMASQ_HOST, DNSMASQ_USER) as conn:
            # Primary config
            main = conn.send_command("cat /etc/dnsmasq.conf", read_timeout=60)
            rel_main = _safe_relpath("etc/dnsmasq.conf")
            if rel_main:
                _write_text(os.path.join(snap_dir, rel_main), (main or ""))
                rel_files.append(rel_main)

            # Directory config fragments
            listing = conn.send_command("ls -1 /etc/dnsmasq.d 2>/dev/null || true", read_timeout=60)
            names = []
            for line in (listing or "").splitlines():
                n = line.strip()
                if not n:
                    continue
                if "/" in n or "\x00" in n:
                    continue
                names.append(n)
            names.sort()

            for n in names:
                # Best effort: only regular files.
                cmd = f"test -f /etc/dnsmasq.d/{n} && cat /etc/dnsmasq.d/{n} || true"
                body = conn.send_command(cmd, read_timeout=60) or ""
                rel = _safe_relpath(f"etc/dnsmasq.d/{n}")
                if rel:
                    _write_text(os.path.join(snap_dir, rel), body)
                    rel_files.append(rel)
        return DnsmasqSnapshot(snapshot_dir=snap_dir, files=rel_files), None
    except Exception as e:
        return None, f"Failed to fetch dnsmasq config via SSH: {type(e).__name__}: {e}"


def load_and_parse_snapshot(snapshot: DnsmasqSnapshot) -> Dict[str, List[str]]:
    """
    Load the locally-snapshotted files and return parsed config lines by file.
    """
    out: Dict[str, List[str]] = {}
    for rel in snapshot.files:
        abs_path = os.path.join(snapshot.snapshot_dir, rel)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            text = ""
        out[rel] = _parse_dnsmasq_lines(text)
    return out

