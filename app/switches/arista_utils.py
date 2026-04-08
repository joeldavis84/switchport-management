import errno
import hashlib
import json
import logging
from typing import Optional

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
