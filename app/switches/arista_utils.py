import errno
import hashlib
import json
import logging
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

                data['interfaces'].append({
                    'name': intf_name,
                    'description': normalize_port_description(intf_info.get('description') or ''),
                    'mode': mode,
                    'access_vlan': access_vlan,
                    'trunk_vlans': trunk_vlans
                })
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


def get_switch_logging_last(
    ip: str, username: str, last_n: int = 50
) -> Tuple[Optional[str], Optional[str]]:
    """Runs `show logging last <n>` on the switch (EOS)."""
    try:
        n = max(1, min(int(last_n), 500))
    except (TypeError, ValueError):
        n = 50
    try:
        with get_connection(ip, username) as net_connect:
            net_connect.enable()
            out = net_connect.send_command(
                f"show logging last {n}",
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
