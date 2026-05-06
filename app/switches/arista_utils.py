import errno
import hashlib
import ipaddress
import json
import logging
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

import paramiko
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logger = logging.getLogger(__name__)

# Netmiko disables cmd_verify for any command matching this pattern (see send_config_set).
# Include description lines: EOS echo can differ from what we sent (spacing/quotes), which
# would break echo verification while the config still applies.
_CONFIG_SET_BYPASS = r"^(banner .*|description .*)$"


def normalize_port_description(text: Optional[str]) -> str:
    """
    Strip one pair of matching outer ASCII quotes from a port description.

    EOS JSON and copy-paste from `show run` sometimes carry CLI-style wrapping quotes.
    Sending `description "foo"` stores quote characters on the port; we send `description foo`.
    """
    if not text:
        return ""
    s = text.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1].strip()
    return s


def format_connection_error(host: str, username: str, exc: BaseException) -> str:
    """Map netmiko/paramiko/socket failures to clear, actionable messages."""
    who = f"{host} (SSH user: {username})" if username else str(host)

    if isinstance(exc, NetmikoTimeoutException):
        return (
            f"SSH timed out to {who}. Check routing, firewalls, and that TCP port 22 is open on the switch."
        )
    if isinstance(exc, (NetmikoAuthenticationException, paramiko.AuthenticationException)):
        return (
            f"SSH authentication failed for {who}. "
            "Confirm the username and that this process can use a key under ~/.ssh (or your SSH agent)."
        )
    if isinstance(exc, paramiko.SSHException):
        return f"SSH error for {who}: {exc}"

    if isinstance(exc, ConnectionRefusedError):
        return (
            f"Connection refused to {host}:22. SSH may be disabled, the port may differ, or a firewall rejected the connection."
        )

    if isinstance(exc, TimeoutError):
        return f"Timed out reaching {who} (socket-level timeout)."

    if isinstance(exc, OSError) and exc.errno is not None:
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return f"No route to host {host} (network unreachable)."
        if exc.errno == errno.ECONNREFUSED:
            return (
                f"Connection refused to {host}:22. SSH may not be listening or the address may be wrong."
            )

    if isinstance(exc, OSError):
        return f"Network error connecting to {who}: {type(exc).__name__}: {exc}"

    return f"Could not complete SSH session to {who}: {type(exc).__name__}: {exc}"


def get_connection(ip, username):
    # use_keys=True makes netmiko pass look_for_keys to Paramiko internally; it is not a ConnectHandler kwarg.
    return ConnectHandler(
        device_type='arista_eos',
        host=ip,
        username=username,
        use_keys=True,
        key_file="/root/.ssh/id_rsa",
        allow_agent=True,
    )

def _ethernet_interface_sort_key(name: str) -> Tuple[int, int, str]:
    """
    Sort key for names like Ethernet1/3: first by the number before '/', then by
    the number immediately after the first '/'. Names without a slash use port 0.
    """
    m = re.match(r"^Ethernet(\d+)/(\d+)", name, re.IGNORECASE)
    if m:
        return (int(m.group(1)), int(m.group(2)), "")
    m = re.match(r"^Ethernet(\d+)\s*$", name, re.IGNORECASE)
    if m:
        return (int(m.group(1)), 0, "")
    return (2**31, 2**31, name.lower())


def get_config_hash(ip, username):
    try:
        with get_connection(ip, username) as net_connect:
            run_config = net_connect.send_command("show running-config")
            return hashlib.md5(run_config.encode('utf-8')).hexdigest(), None
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("get_config_hash failed for %s: %s", ip, msg)
        return None, msg


def get_switch_data(ip, username):
    data = {'vlans': [], 'interfaces': [], 'hash': None, 'error': None}
    try:
        with get_connection(ip, username) as net_connect:
            # Get Hash
            run_config = net_connect.send_command("show running-config")
            data['hash'] = hashlib.md5(run_config.encode('utf-8')).hexdigest()

            # Get VLANs
            vlan_out = net_connect.send_command("show vlan | json")
            vlan_json = json.loads(vlan_out)
            for v_id, v_info in vlan_json.get('vlans', {}).items():
                data['vlans'].append({'id': v_id, 'name': v_info.get('name', '')})

            # Get Interfaces
            intf_out = net_connect.send_command("show interfaces | json")
            intf_json = json.loads(intf_out)
            
            switchport_out = net_connect.send_command("show interfaces switchport | json")
            switchport_json = json.loads(switchport_out)

            for intf_name, intf_info in intf_json.get('interfaces', {}).items():
                if not intf_name.startswith("Ethernet"):
                    continue
                
                sp_info = switchport_json.get('switchports', {}).get(intf_name, {})
                mode = sp_info.get('switchportInfo', {}).get('mode', 'access')
                
                access_vlan = str(sp_info.get('switchportInfo', {}).get('accessVlanId', 1))
                trunk_vlans = sp_info.get('switchportInfo', {}).get('trunkAllowedVlans', '1-4094')

                # EOS: interfaceStatus "disabled" = administratively shutdown
                status = (intf_info.get('interfaceStatus') or '').lower()
                admin_up = status != 'disabled'

                data['interfaces'].append({
                    'name': intf_name,
                    'description': normalize_port_description(intf_info.get('description') or ''),
                    'mode': mode,
                    'access_vlan': access_vlan,
                    'trunk_vlans': trunk_vlans,
                    'admin_up': admin_up,
                })

            data["interfaces"].sort(
                key=lambda row: _ethernet_interface_sort_key(row["name"])
            )
    except json.JSONDecodeError as e:
        data['error'] = (
            f"SSH to {ip} worked, but switch output was not valid JSON (position {e.pos}). "
            "The device may not be Arista EOS or CLI output may have changed."
        )
        logger.warning("get_switch_data JSON error for %s: %s", ip, data['error'])
    except Exception as e:
        data['error'] = format_connection_error(ip, username, e)
        logger.warning("get_switch_data failed for %s: %s", ip, data['error'])
    return data


def push_switch_config(ip, username, interface, description, mode, selected_vlans):
    try:
        with get_connection(ip, username) as net_connect:
            net_connect.enable()
            commands = [f"interface {interface}"]
            desc = normalize_port_description(description)

            if desc:
                # One line: everything after the first space is the description text (EOS CLI).
                commands.append(f"description {desc}")
            else:
                commands.append("no description")

            commands.append(f"switchport mode {mode}")
            
            if mode == 'access':
                vlan = selected_vlans[0] if selected_vlans else "1"
                commands.append(f"switchport access vlan {vlan}")
            elif mode == 'trunk':
                vlan_str = ",".join(selected_vlans) if selected_vlans else "none"
                commands.append(f"switchport trunk allowed vlan {vlan_str}")

            net_connect.send_config_set(commands, bypass_commands=_CONFIG_SET_BYPASS)
            net_connect.send_command("write memory")
            return True, None
    except json.JSONDecodeError as e:
        msg = (
            f"SSH to {ip} worked, but could not parse command output as JSON (position {e.pos})."
        )
        logger.warning("push_switch_config JSON error for %s: %s", ip, msg)
        return False, msg
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("push_switch_config failed for %s: %s", ip, msg)
        return False, msg


def push_interface_admin_state(ip: str, username: str, interface: str, enabled: bool):
    """Apply `shutdown` or `no shutdown` on an interface and save to startup-config."""
    try:
        with get_connection(ip, username) as net_connect:
            net_connect.enable()
            commands = [f"interface {interface}"]
            if enabled:
                commands.append("no shutdown")
            else:
                commands.append("shutdown")
            net_connect.send_config_set(commands, bypass_commands=_CONFIG_SET_BYPASS)
            net_connect.send_command("write memory")
            return True, None
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("push_interface_admin_state failed for %s %s: %s", ip, interface, msg)
        return False, msg


def get_arp_table(ip, username):
    """Fetches the ARP table from the Arista switch."""
    try:
        with get_connection(ip, username) as net_connect:
            arp_out = net_connect.send_command("show arp | json")
            arp_json = json.loads(arp_out)
            # Arista stores ARP entries under 'ipv4Neighbors'
            return arp_json.get('ipV4Neighbors', []), None
    except json.JSONDecodeError as e:
        msg = (
            f"SSH to {ip} worked, but ARP output was not valid JSON (position {e.pos})."
        )
        logger.warning("get_arp_table JSON error for %s: %s", ip, msg)
        return [], msg
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("get_arp_table failed for %s: %s", ip, msg)
        return [], msg


def _dns_label_ok(label: str) -> bool:
    """RFC 1035-style DNS label: 1–63 chars, letters/digits/hyphen, no leading/trailing hyphen."""
    if not label or len(label) > 63:
        return False
    if label[0] == "-" or label[-1] == "-":
        return False
    return bool(re.match(r"^[A-Za-z0-9-]+$", label))


def _valid_ping_hostname_or_fqdn(s: str) -> bool:
    """
    Short hostname (no '.') or FQDN (at least one '.', optional trailing '.').

    Only ASCII letters, digits, hyphen, and period; no '..' or empty labels.
    """
    if not s or len(s) > 253:
        return False
    if not re.match(r"^[A-Za-z0-9.-]+$", s):
        return False
    if ".." in s:
        return False
    if "." not in s:
        return _dns_label_ok(s)
    body = s.rstrip(".")
    if not body:
        return False
    if "." in body:
        labels = body.split(".")
        if any(not lbl for lbl in labels):
            return False
        return all(_dns_label_ok(lbl) for lbl in labels)
    return s.endswith(".") and _dns_label_ok(body)


def run_switch_ping(
    ip: str, username: str, target_raw: str
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Run a bounded ICMP ping from the switch (EOS) to a validated destination.

    Accepts a literal IPv4/IPv6 address (no CIDR or zone suffix), a short hostname
    (no period), or an FQDN (at least one period, optional trailing period). IP
    literals use the parsed ipaddress form in the CLI; hostnames must pass strict
    ASCII label checks so the token cannot carry shell/CLI metacharacters.

    Returns (eos_command, switch_output, error). On validation or connection
    failure, output is None and error is set; eos_command may still be set if
    the command was known before failure.
    """
    raw = (target_raw or "").strip()
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        if not _valid_ping_hostname_or_fqdn(raw):
            return (
                None,
                None,
                "Enter a valid IPv4/IPv6 address, short hostname, or FQDN "
                "(ASCII letters, digits, hyphen; FQDN needs at least one period).",
            )
        cmd = f"ping {raw} repeat 5"
    else:
        if addr.version == 4:
            cmd = f"ping {addr.compressed} repeat 5"
        else:
            cmd = f"ping ipv6 {addr.compressed} repeat 5"

    try:
        with get_connection(ip, username) as net_connect:
            net_connect.enable()
            out = net_connect.send_command(cmd, read_timeout=120)
        text = (out or "").strip() if out is not None else ""
        return cmd, text, None
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("run_switch_ping failed for %s to %s: %s", ip, raw, msg)
        return cmd, None, msg


def run_switch_getent_hosts(
    ip: str, username: str, target_raw: str
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Run `bash getent hosts <name>` on EOS for a validated target.

    Accepts the same literal IP and hostname/FQDN rules as ping (strict tokens only;
    the argument passed to bash is shell-quoted).

    Returns (full_command, stdout_text, error).
    """
    raw = (target_raw or "").strip()
    try:
        addr = ipaddress.ip_address(raw)
        token = addr.compressed
    except ValueError:
        if not _valid_ping_hostname_or_fqdn(raw):
            return (
                None,
                None,
                "Enter a valid IPv4/IPv6 address, short hostname, or FQDN "
                "(ASCII letters, digits, hyphen; FQDN needs at least one period).",
            )
        token = raw
    quoted = shlex.quote(token)
    cmd = f"bash getent hosts {quoted}"
    try:
        with get_connection(ip, username) as net_connect:
            net_connect.enable()
            out = net_connect.send_command(cmd, read_timeout=90)
        text = (out or "").strip() if out is not None else ""
        return cmd, text, None
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("run_switch_getent_hosts failed for %s to %s: %s", ip, raw, msg)
        return cmd, None, msg


_NAME_SERVER_LINE_RE = re.compile(
    r"^ip name-server(?:\s+vrf\s+(\S+))?\s+(\S+)\s*$",
    re.IGNORECASE,
)

_DOMAIN_LIST_LINE_RE = re.compile(r"^ip domain-list\s+(.+)$", re.IGNORECASE)


def _global_name_server_line_ok(vrf: Optional[str]) -> bool:
    """True if this name-server line applies to default / global (non-VRF) context."""
    if vrf is None:
        return True
    return vrf.lower() == "default"


def _parse_name_server_running_line(line: str) -> Optional[Tuple[str, str]]:
    """
    Parse one running-config line for ip name-server.

    Returns (no_command_line, normalized_ip) for global/default VRF lines only;
    otherwise None.
    """
    s = line.strip()
    if not s.startswith("ip name-server"):
        return None
    m = _NAME_SERVER_LINE_RE.match(s)
    if not m:
        return None
    vrf, addr_token = m.group(1), m.group(2).strip()
    if not _global_name_server_line_ok(vrf):
        return None
    try:
        ipaddress.ip_address(addr_token)
    except ValueError:
        return None
    return ("no " + s, str(ipaddress.ip_address(addr_token)))


def _parse_domain_list_running_line(line: str) -> Optional[Tuple[str, str]]:
    """Returns (no_command_line, domain) for ip domain-list lines."""
    s = line.strip()
    m = _DOMAIN_LIST_LINE_RE.match(s)
    if not m:
        return None
    dom = m.group(1).strip()
    if (len(dom) >= 2 and dom[0] == dom[-1] == '"') or (dom[:1] == "'" and dom[-1:] == "'"):
        dom = dom[1:-1].strip()
    if not _valid_ping_hostname_or_fqdn(dom):
        return None
    return ("no " + s, dom)


def get_switch_dns_global(
    ip: str, username: str
) -> Tuple[Optional[Dict[str, List[str]]], Optional[str]]:
    """
    Read global (default VRF) DNS name servers and domain search list from running-config.

    Returns ({"name_servers": [...], "domain_search": [...]}, None) on success.
    """
    try:
        with get_connection(ip, username) as net_connect:
            net_connect.enable()
            ns_block = net_connect.send_command(
                "show running-config | include ip name-server",
                read_timeout=90,
            )
            dl_block = net_connect.send_command(
                "show running-config | include ip domain-list",
                read_timeout=90,
            )
        name_servers: List[str] = []
        seen_ns: set = set()
        for line in (ns_block or "").splitlines():
            parsed = _parse_name_server_running_line(line)
            if not parsed:
                continue
            _, norm = parsed
            if norm not in seen_ns:
                seen_ns.add(norm)
                name_servers.append(norm)

        domain_search: List[str] = []
        seen_dom: set = set()
        for line in (dl_block or "").splitlines():
            parsed = _parse_domain_list_running_line(line)
            if not parsed:
                continue
            _, dom = parsed
            if dom not in seen_dom:
                seen_dom.add(dom)
                domain_search.append(dom)

        return {"name_servers": name_servers, "domain_search": domain_search}, None
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("get_switch_dns_global failed for %s: %s", ip, msg)
        return None, msg


def _validate_dns_apply_lists(
    name_servers: Any, domain_search: Any
) -> Tuple[Optional[List[str]], Optional[List[str]], Optional[str]]:
    """Normalize and validate JSON lists for apply_switch_dns_global."""
    if name_servers is None:
        ns_raw: List[str] = []
    elif isinstance(name_servers, list):
        ns_raw = [str(x).strip() for x in name_servers]
    else:
        return None, None, "name_servers must be a list of addresses."

    if domain_search is None:
        ds_raw: List[str] = []
    elif isinstance(domain_search, list):
        ds_raw = [str(x).strip() for x in domain_search]
    else:
        return None, None, "domain_search must be a list of domain strings."

    out_ns: List[str] = []
    seen_ns: set = set()
    for s in ns_raw:
        if not s:
            continue
        try:
            norm = str(ipaddress.ip_address(s))
        except ValueError:
            return None, None, f"Invalid name server address: {s!r}."
        if norm not in seen_ns:
            seen_ns.add(norm)
            out_ns.append(norm)

    out_dom: List[str] = []
    seen_dom: set = set()
    for d in ds_raw:
        if not d:
            continue
        if not _valid_ping_hostname_or_fqdn(d):
            return None, None, f"Invalid domain search entry: {d!r}."
        if d not in seen_dom:
            seen_dom.add(d)
            out_dom.append(d)

    return out_ns, out_dom, None


def apply_switch_dns_global(
    ip: str, username: str, name_servers: Any, domain_search: Any
) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Replace global (default VRF) ip name-server and ip domain-list entries, then
    write memory.

    Returns (cli_transcript, error, new_config_hash). new_config_hash is set
    only on full success.
    """
    out_ns, out_dom, verr = _validate_dns_apply_lists(name_servers, domain_search)
    if verr:
        return "", verr, None

    log_parts: List[str] = []
    try:
        with get_connection(ip, username) as net_connect:
            net_connect.enable()
            cur_ns = net_connect.send_command(
                "show running-config | include ip name-server",
                read_timeout=90,
            )
            cur_dl = net_connect.send_command(
                "show running-config | include ip domain-list",
                read_timeout=90,
            )

            removals: List[str] = []
            for line in (cur_ns or "").splitlines():
                parsed = _parse_name_server_running_line(line)
                if parsed:
                    removals.append(parsed[0])
            for line in (cur_dl or "").splitlines():
                parsed = _parse_domain_list_running_line(line)
                if parsed:
                    removals.append(parsed[0])

            uniq_removals: List[str] = []
            for r in removals:
                if r not in uniq_removals:
                    uniq_removals.append(r)
            removals = uniq_removals

            additions: List[str] = []
            for ns in out_ns:
                additions.append(f"ip name-server vrf default {ns}")
            for dom in out_dom:
                additions.append(f"ip domain-list {dom}")

            cfg_cmds = removals + additions + ["write memory"]
            log_parts.append("! entering configuration mode\n")
            cfg_out = net_connect.send_config_set(cfg_cmds, bypass_commands=_CONFIG_SET_BYPASS)
            log_parts.append(cfg_out or "")
            log_parts.append("\n! verify: name servers\n")
            log_parts.append(
                net_connect.send_command(
                    "show running-config | include ip name-server",
                    read_timeout=60,
                )
                or ""
            )
            log_parts.append("\n! verify: domain search\n")
            log_parts.append(
                net_connect.send_command(
                    "show running-config | include ip domain-list",
                    read_timeout=60,
                )
                or ""
            )

        h, herr = get_config_hash(ip, username)
        if herr:
            logger.warning("apply_switch_dns_global: hash after apply failed for %s: %s", ip, herr)
        return "".join(log_parts).strip(), None, h
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("apply_switch_dns_global failed for %s: %s", ip, msg)
        return "\n".join(log_parts).strip(), msg, None


def get_switch_logging_last(
    ip: str, username: str, last_n: int = 50
) -> Tuple[Optional[str], Optional[str]]:
    """Runs `show logging <n>` on the switch (EOS)."""
    try:
        n = max(1, min(int(last_n), 500))
    except (TypeError, ValueError):
        n = 50
    try:
        with get_connection(ip, username) as net_connect:
            net_connect.enable()
            out = net_connect.send_command(
                f"show logging {n}",
                read_timeout=120,
            )
            text = (out or "").strip() if out is not None else ""
            return text, None
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("get_switch_logging_last failed for %s: %s", ip, msg)
        return None, msg


def _vlan_sort_key(row: Dict[str, Any]) -> int:
    vid = row.get("id", "0")
    try:
        return int(str(vid).split("-", 1)[0])
    except ValueError:
        return 0


def _vlan_disabled(v_info: Dict[str, Any]) -> bool:
    """True if VLAN is suspended / not forwarding (red X in UI)."""
    st = str(v_info.get("status") or "").lower()
    if "suspend" in st or "inactive" in st:
        return True
    if v_info.get("suspended") is True:
        return True
    state = str(v_info.get("state") or "").lower()
    if "suspend" in state:
        return True
    return False


def _vlan_description_field(v_info: Dict[str, Any]) -> str:
    """EOS may expose description separately from name (varies by version)."""
    for key in ("description", "vlanDescription", "comment"):
        val = v_info.get(key)
        if val is None:
            continue
        if isinstance(val, str):
            s = val.strip()
            if s:
                return s
    return ""


def _vlan_detail_skip_interface(if_name: str) -> bool:
    """True for internal EOS interfaces that should not appear on the VLAN ports table."""
    n = str(if_name).strip().lower()
    return n == "cpu"


def _interface_names_from_vlan_json(v_info: Dict[str, Any]) -> List[str]:
    ifaces = v_info.get("interfaces")
    if isinstance(ifaces, dict):
        return sorted(k for k in ifaces.keys() if not _vlan_detail_skip_interface(k))
    if isinstance(ifaces, list):
        return sorted(str(x) for x in ifaces if not _vlan_detail_skip_interface(str(x)))
    return []


def _trunk_spec_includes_vlan(spec: str, vid: int) -> bool:
    """Best-effort parse of EOS trunk allowed VLAN list (e.g. 10,20,30-40,1-4094)."""
    spec = spec.strip().lower()
    if spec in ("", "none"):
        return False
    if spec in ("1-4094", "all"):
        return True
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            try:
                lo, hi = int(lo_s), int(hi_s)
                if lo <= vid <= hi:
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(part) == vid:
                    return True
            except ValueError:
                continue
    return False


def _fallback_interfaces_for_vlan(sw_json: Dict[str, Any], vlan_id: int) -> List[str]:
    """When show vlan omits interface keys, infer ports from switchport JSON."""
    vid = int(vlan_id)
    switchports = sw_json.get("switchports") or {}
    found: List[str] = []
    for if_name, data in switchports.items():
        n = str(if_name)
        if not (n.startswith("Ethernet") or n.startswith("Port-Channel")):
            continue
        sp = (data or {}).get("switchportInfo") or {}
        mode = str(sp.get("mode") or "").lower()
        if mode == "access":
            av = sp.get("accessVlanId")
            try:
                if av is not None and int(av) == vid:
                    found.append(str(if_name))
            except (TypeError, ValueError):
                continue
        elif mode == "trunk":
            raw = sp.get("trunkAllowedVlans")
            if raw is not None and _trunk_spec_includes_vlan(str(raw), vid):
                found.append(str(if_name))
    return sorted(found)


def get_vlan_table(ip: str, username: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Read configured VLANs from the switch (show vlan | json)."""
    try:
        with get_connection(ip, username) as net_connect:
            vlan_out = net_connect.send_command("show vlan | json")
            vlan_json = json.loads(vlan_out)
            rows: List[Dict[str, Any]] = []
            for v_id, v_info in vlan_json.get("vlans", {}).items():
                if not isinstance(v_info, dict):
                    continue
                name = v_info.get("name") or ""
                if isinstance(name, str):
                    name = name.strip()
                row: Dict[str, Any] = {
                    "id": str(v_id),
                    "name": name,
                    "description": _vlan_description_field(v_info),
                    "disabled": _vlan_disabled(v_info),
                }
                rows.append(row)
            rows.sort(key=_vlan_sort_key)
            return rows, None
    except json.JSONDecodeError as e:
        msg = (
            f"SSH to {ip} worked, but VLAN output was not valid JSON (position {e.pos})."
        )
        logger.warning("get_vlan_table JSON error for %s: %s", ip, msg)
        return [], msg
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("get_vlan_table failed for %s: %s", ip, msg)
        return [], msg


def get_vlan_detail(
    ip: str, username: str, vlan_id: int
) -> Tuple[Optional[Dict[str, Any]], Optional[str], bool]:
    """
    Ports using vlan_id (from show vlan + switchport + interface descriptions).

    Returns (payload, error, not_found). payload is set only on success.
    """
    vid_str = str(vlan_id)
    try:
        with get_connection(ip, username) as net_connect:
            vlan_out = net_connect.send_command("show vlan | json")
            vlan_json = json.loads(vlan_out)
            sw_out = net_connect.send_command("show interfaces switchport | json")
            sw_json = json.loads(sw_out)
            intf_out = net_connect.send_command("show interfaces | json")
            intf_json = json.loads(intf_out)
            interfaces_map = intf_json.get("interfaces") or {}

            vlans = vlan_json.get("vlans") or {}
            v_info = vlans.get(vid_str)
            if v_info is None and vid_str.isdigit():
                v_info = vlans.get(str(int(vid_str)))
            if not isinstance(v_info, dict):
                return None, None, True

            switchports = sw_json.get("switchports") or {}
            if_names = sorted(
                n
                for n in (
                    set(_interface_names_from_vlan_json(v_info))
                    | set(_fallback_interfaces_for_vlan(sw_json, vlan_id))
                )
                if not _vlan_detail_skip_interface(n)
            )

            port_rows: List[Dict[str, Any]] = []
            for if_name in if_names:
                sp = switchports.get(if_name, {}).get("switchportInfo") or {}
                mode = str(sp.get("mode") or "").lower() or "—"
                raw_if_desc = (interfaces_map.get(if_name) or {}).get("description")
                if raw_if_desc is None:
                    raw_if_desc = ""
                elif not isinstance(raw_if_desc, str):
                    raw_if_desc = str(raw_if_desc)
                if_desc = normalize_port_description(raw_if_desc)
                trunk_raw = sp.get("trunkAllowedVlans")
                trunk_vlans = str(trunk_raw).strip() if trunk_raw is not None else ""
                additional = trunk_vlans if mode == "trunk" else ""
                port_rows.append(
                    {
                        "name": if_name,
                        "description": if_desc,
                        "mode": mode,
                        "additional_info": additional,
                    }
                )

            payload = {
                "vlan_id": vid_str,
                "name": (v_info.get("name") or "").strip() if isinstance(v_info.get("name"), str) else "",
                "description": _vlan_description_field(v_info),
                "disabled": _vlan_disabled(v_info),
                "ports": port_rows,
            }
            return payload, None, False
    except json.JSONDecodeError as e:
        msg = (
            f"SSH to {ip} worked, but command output was not valid JSON (position {e.pos})."
        )
        logger.warning("get_vlan_detail JSON error for %s vlan %s: %s", ip, vlan_id, msg)
        return None, msg, False
    except Exception as e:
        msg = format_connection_error(ip, username, e)
        logger.warning("get_vlan_detail failed for %s vlan %s: %s", ip, vlan_id, msg)
        return None, msg, False
