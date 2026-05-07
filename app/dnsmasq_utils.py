import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

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


_DNS_GLOBAL_KEYS = {
    "domain-needed",
    "bogus-priv",
    "no-resolv",
    "resolv-file",
    "server",
    "no-hosts",
    "addn-hosts",
    "hostsdir",
    "domain",
    "local",
    "expand-hosts",
    "local-ttl",
    "neg-ttl",
    "cache-size",
    "min-cache-ttl",
    "max-cache-ttl",
    "dns-forward-max",
    "listen-address",
    "interface",
    "except-interface",
    "bind-interfaces",
    "bind-dynamic",
    "strict-order",
    "edns-packet-max",
}

_DNS_ZONE_KEYS = {
    "server",
    "local",
    "address",
    "cname",
    "ptr-record",
    "txt-record",
    "mx-host",
    "srv-host",
    "host-record",
    "naptr-record",
}


def _fmt_directive(key: str, value: Optional[str]) -> str:
    if value is None or value == "":
        return key
    # Augeas typically provides the RHS; dnsmasq uses key=value style.
    if value.startswith("="):
        return f"{key}{value}"
    return f"{key}={value}"


def _try_get_augeas() -> Tuple[Optional[Any], Optional[str]]:
    try:
        from augeas import Augeas  # type: ignore
    except Exception as e:
        return None, f"Augeas python bindings are not available: {type(e).__name__}: {e}"
    return Augeas, None


def _dnsmasq_file_tree_paths(snapshot: DnsmasqSnapshot) -> List[str]:
    """
    Convert snapshot-relative file paths like etc/dnsmasq.conf into augeas /files paths.
    """
    out: List[str] = []
    for rel in snapshot.files:
        # Snapshot uses rel paths without leading slash.
        rel = rel.strip().lstrip("/")
        if not rel.startswith("etc/"):
            continue
        out.append("/files/" + rel)
    return out


def parse_dnsmasq_dns_only(snapshot: DnsmasqSnapshot) -> Tuple[Optional[Dict[str, List[str]]], Optional[str]]:
    """
    Parse the snapshotted dnsmasq config using Augeas and return DNS-only information:
    - globals: selected global DNS directives
    - zones: zone/override directives (server/local/address/etc.)
    """
    Augeas, err = _try_get_augeas()
    if err:
        return None, err

    try:
        aug = Augeas(root=snapshot.snapshot_dir)
        # Explicit transforms: dnsmasq.conf and all files inside dnsmasq.d
        aug.transform("Dnsmasq", "/etc/dnsmasq.conf")
        aug.transform("Dnsmasq", "/etc/dnsmasq.d/*")
        aug.load()
    except Exception as e:
        return None, f"Failed to parse dnsmasq config with Augeas: {type(e).__name__}: {e}"

    globals_out: List[str] = []
    zones_out: List[str] = []

    for base in _dnsmasq_file_tree_paths(snapshot):
        try:
            nodes = aug.match(base + "/*") or []
        except Exception:
            nodes = []
        for node in nodes:
            key = str(node).rsplit("/", 1)[-1]
            # Normalize array-style keys like server[1] -> server
            if "[" in key:
                key0 = key.split("[", 1)[0]
            else:
                key0 = key
            try:
                val = aug.get(node)
            except Exception:
                val = None

            if key0 in _DNS_ZONE_KEYS:
                zones_out.append(_fmt_directive(key0, val))
                continue
            if key0 in _DNS_GLOBAL_KEYS:
                globals_out.append(_fmt_directive(key0, val))
                continue

    # Stable output
    globals_out = sorted(dict.fromkeys(globals_out))
    zones_out = sorted(dict.fromkeys(zones_out))

    return {"globals": globals_out, "zones": zones_out}, None


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

