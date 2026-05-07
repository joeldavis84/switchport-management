import os
import re
import shlex
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


def _node_label(seg: str) -> str:
    """Last path segment basename, stripping Augeas [n] index."""
    leaf = seg.rsplit("/", 1)[-1] if "/" in seg else seg
    if "[" in leaf:
        return leaf.split("[", 1)[0]
    return leaf


def _rel_from_augeas_path(path: str) -> Optional[str]:
    """`/files/etc/dnsmasq.d/foo.conf` -> `etc/dnsmasq.d/foo.conf`."""
    p = path.strip()
    if not p.startswith("/files/etc/"):
        return None
    return p[len("/files/") :].lstrip("/")


_DNS_GLOBAL_KEYS = {
    "domain-needed",
    "bogus-priv",
    "bogus-nxdomain",
    "no-resolv",
    "resolv-file",
    "no-hosts",
    "addn-hosts",
    "hostsdir",
    "domain",
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
    "auth-zone",
    "trust-anchor",
}

_DNS_COMMENT_LABELS = frozenset({"#comment", ";comment", "comment", "Comment"})

_DNS_AMBIGUOUS_KEYS = frozenset({"server", "local"})

_DNS_ZONE_KEYS = {
    "address",
    "cname",
    "ptr-record",
    "txt-record",
    "mx-host",
    "srv-host",
    "host-record",
    "naptr-record",
}

_DNS_MANAGED_KEYS = _DNS_GLOBAL_KEYS | _DNS_ZONE_KEYS | _DNS_AMBIGUOUS_KEYS


def _fmt_directive(key: str, value: Optional[str]) -> str:
    if value is None or value == "":
        return key
    # Augeas typically provides the RHS; dnsmasq uses key=value style.
    if value.startswith("="):
        return f"{key}{value}"
    return f"{key}={value}"


def _numeric_index_suffix(path: str) -> Tuple[int, str]:
    m = re.search(r"\[(\d+)\]$", path.rstrip("/"))
    return (int(m.group(1)), path) if m else (-1, path)


def _collect_leaf_values_ordered(aug: Any, node: str, out: List[str]) -> None:
    """Depth-first: append non-None aug.get values for leaf nodes under node."""
    children = aug.match(node.rstrip("/") + "/*")
    children = sorted(children, key=_numeric_index_suffix)
    if not children:
        try:
            v = aug.get(node)
        except Exception:
            v = None
        if v is not None and v != "":
            out.append(v)
        return
    for c in children:
        _collect_leaf_values_ordered(aug, c, out)


def _format_address_from_augeas(
    aug: Any, directive_node: str, children: List[str]
) -> str:
    """
    Rebuild dnsmasq `address=` from the Augeas Dnsmasq lens tree.

    The lens stores the reply target on the `address` node and path/wildcard
    segments as `domain[n]` children (see augeas tests: address=/a/b/1.2.3.3).
    A naive flatten of all leaves drops the parent value and breaks slash paths.
    """
    ch = sorted(children or [], key=_numeric_index_suffix)
    domain_segs: List[str] = []
    for c in ch:
        if _node_label(c.rsplit("/", 1)[-1]) != "domain":
            continue
        try:
            dv = aug.get(c)
        except Exception:
            dv = None
        if dv is not None and str(dv).strip() != "":
            domain_segs.append(str(dv).strip())
    try:
        ip = aug.get(directive_node)
    except Exception:
        ip = None
    ip_s = str(ip).strip() if ip is not None else ""
    if domain_segs:
        path = "/".join(domain_segs)
        if ip_s:
            return f"address=/{path}/{ip_s}"
        return f"address=/{path}"
    if ip_s:
        return _fmt_directive("address", ip_s)
    return "address"


def _format_directive_subtree(aug: Any, directive_node: str) -> str:
    """
    Pretty one directive line from a top-level Dnsmasq lens subtree
    (e.g. `/files/etc/dnsmasq.conf/server[3]` ...).
    """
    label = _node_label(directive_node.rsplit("/", 1)[-1])
    children = aug.match(directive_node.rstrip("/") + "/*")
    if label == "address" and children:
        return _format_address_from_augeas(aug, directive_node, list(children))
    if not children:
        try:
            v = aug.get(directive_node)
        except Exception:
            v = None
        if v is None or v == "":
            return label
        return _fmt_directive(label, v)
    parts: List[str] = []
    _collect_leaf_values_ordered(aug, directive_node, parts)
    if not parts:
        try:
            v = aug.get(directive_node)
        except Exception:
            v = None
        if v is None or v == "":
            return label
        return _fmt_directive(label, v)
    if label == "server" and parts:
        rhs = " ".join(parts).strip()
        return _fmt_directive(label, rhs) if rhs else label

    # Default: flattened RHS (often still readable for globals with simple values).
    joined = " ".join(parts).strip()
    return _fmt_directive(label, joined) if joined else label


def _directive_has_domain_subtree(aug: Any, node: str) -> bool:
    """True when this top-level directive has immediate `domain[...]` children (zone-scoped)."""
    for c in aug.match(node.rstrip("/") + "/*") or []:
        if _node_label(c.rsplit("/", 1)[-1]) == "domain":
            return True
    return False


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
    out.sort(key=lambda x: (
        (0 if "dnsmasq.conf" in x and "dnsmasq.d" not in x else 1),
        x,
    ))
    return out


def parse_dnsmasq_dns_only(snapshot: DnsmasqSnapshot) -> Tuple[
    Optional[Dict[str, Any]], Optional[str]
]:
    """
    Parse the snapshotted dnsmasq config using Augeas: walk each file's Dnsmasq tree
    and emit structured DNS-only items.

    Returns:
      globals: list of {"directive", "display", "source", "augeas_path"}
      zones: same shape
      parse_errors: optional list of {path, message} from Augeas
    """
    Augeas, err = _try_get_augeas()
    if err:
        return None, err

    try:
        aug = Augeas(root=snapshot.snapshot_dir)
        # Register lens for every snapshotted file (wildcard transform is unreliable
        # for load on some hosts).
        aug.transform("Dnsmasq", "/etc/dnsmasq.conf")
        for base in _dnsmasq_file_tree_paths(snapshot):
            rel = base[len("/files/") :].lstrip("/") if base.startswith("/files/") else ""
            if rel and rel.startswith("etc/dnsmasq.d/"):
                aug.transform("Dnsmasq", "/" + rel)
        aug.load()
    except Exception as e:
        return None, f"Failed to parse dnsmasq config with Augeas: {type(e).__name__}: {e}"

    parse_errors: List[Dict[str, str]] = []
    errs_fn = getattr(aug, "errors", None)
    if callable(errs_fn):
        try:
            for rec in errs_fn():
                if isinstance(rec, tuple) or isinstance(rec, list):
                    tup = tuple(rec)
                    path = str(tup[0]) if len(tup) > 0 else ""
                    msg = str(tup[2]) if len(tup) > 2 else str(tup[-1])
                    parse_errors.append({"path": path, "message": msg})
                else:
                    parse_errors.append({"path": "", "message": str(rec)})
        except Exception:
            parse_errors.append(
                {"path": "", "message": "Augeas reported errors but they could not be read."}
            )

    globals_items: List[Dict[str, str]] = []
    zones_items: List[Dict[str, str]] = []

    for base in _dnsmasq_file_tree_paths(snapshot):
        source = _rel_from_augeas_path(base) or base
        try:
            top_nodes = sorted(aug.match(base.rstrip("/") + "/*") or [], key=lambda p: p)
        except Exception:
            top_nodes = []

        for node in top_nodes:
            label = _node_label(node.rsplit("/", 1)[-1])
            if label in _DNS_COMMENT_LABELS or label == "empty":
                continue
            if label not in _DNS_MANAGED_KEYS:
                continue
            display = _format_directive_subtree(aug, node).strip()
            if not display:
                continue

            item = {
                "directive": label,
                "display": display,
                "source": source,
                "augeas_path": node,
            }
            if label in _DNS_AMBIGUOUS_KEYS:
                if _directive_has_domain_subtree(aug, node):
                    zones_items.append(item)
                else:
                    globals_items.append(item)
            elif label in _DNS_ZONE_KEYS:
                zones_items.append(item)
            elif label in _DNS_GLOBAL_KEYS:
                globals_items.append(item)

    def _sort_key(it: Dict[str, str]) -> Tuple[str, str, str]:
        return (it.get("source") or "", it.get("directive") or "", it.get("display") or "")

    globals_items.sort(key=_sort_key)
    zones_items.sort(key=_sort_key)

    return {
        "globals": globals_items,
        "zones": zones_items,
        "parse_errors": parse_errors,
    }, None


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
            find_out = conn.send_command(
                "find /etc/dnsmasq.d -maxdepth 1 -type f 2>/dev/null | LC_ALL=C sort",
                read_timeout=120,
            )
            paths_found: List[str] = []
            for line in (find_out or "").splitlines():
                p = line.strip()
                if not p.startswith("/etc/dnsmasq.d/"):
                    continue
                if "\x00" in p or ".." in p:
                    continue
                paths_found.append(p)
            paths_found.sort()

            for fp in paths_found:
                basename = fp.rsplit("/", 1)[-1]
                if not basename:
                    continue
                body = conn.send_command(
                    f"cat {shlex.quote(fp)} 2>/dev/null || true", read_timeout=120
                ) or ""
                rel = _safe_relpath(f"etc/dnsmasq.d/{basename}")
                if rel:
                    _write_text(os.path.join(snap_dir, rel), body)
                    rel_files.append(rel)
        rel_files.sort(
            key=lambda r: (0 if r == "etc/dnsmasq.conf" else 1, r),
        )
        return DnsmasqSnapshot(snapshot_dir=snap_dir, files=rel_files), None
    except Exception as e:
        return None, f"Failed to fetch dnsmasq config via SSH: {type(e).__name__}: {e}"

