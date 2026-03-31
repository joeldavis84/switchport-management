import json
import hashlib
from netmiko import ConnectHandler

def get_connection(ip, username):
    # netmiko automatically looks in ~/.ssh/ if use_keys=True
    return ConnectHandler(
        device_type='arista_eos',
        host=ip,
        username=username,
        use_keys=True,
        look_for_keys=True,
        allow_agent=True
    )

def get_config_hash(ip, username):
    try:
        with get_connection(ip, username) as net_connect:
            run_config = net_connect.send_command("show running-config")
            return hashlib.md5(run_config.encode('utf-8')).hexdigest()
    except Exception as e:
        return None

def get_switch_data(ip, username):
    data = {'vlans': [], 'interfaces': [], 'hash': None}
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
                    'description': intf_info.get('description', ''),
                    'mode': mode,
                    'access_vlan': access_vlan,
                    'trunk_vlans': trunk_vlans
                })
    except Exception as e:
        print(f"Error connecting to {ip}: {e}")
    return data

def push_switch_config(ip, username, interface, description, mode, selected_vlans):
    try:
        with get_connection(ip, username) as net_connect:
            net_connect.enable()
            commands = [f"interface {interface}"]
            
            if description:
                commands.append(f"description {description}")
            else:
                commands.append("no description")

            commands.append(f"switchport mode {mode}")
            
            if mode == 'access':
                vlan = selected_vlans[0] if selected_vlans else "1"
                commands.append(f"switchport access vlan {vlan}")
            elif mode == 'trunk':
                vlan_str = ",".join(selected_vlans) if selected_vlans else "none"
                commands.append(f"switchport trunk allowed vlan {vlan_str}")

            net_connect.send_config_set(commands)
            net_connect.send_command("write memory")
            return True
    except Exception as e:
        print(f"Error pushing config to {ip}: {e}")
        return False

def get_arp_table(ip, username):
    """Fetches the ARP table from the Arista switch."""
    try:
        with get_connection(ip, username) as net_connect:
            arp_out = net_connect.send_command("show arp | json")
            arp_json = json.loads(arp_out)
            # Arista stores ARP entries under 'ipv4Neighbors'
            return arp_json.get('ipv4Neighbors', [])
    except Exception as e:
        print(f"Error fetching ARP table from {ip}: {e}")
        return []
