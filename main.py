import requests
from ipaddress import ip_network
import pandas as pd
from tabulate import tabulate
from creds import FMC_URL, USERNAME, PASSWORD, DOMAIN

# Endpoints
AUTH_ENDPOINT = "/api/fmc_platform/v1/auth/generatetoken"
DEVICES_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords?expanded=true"
ACCESS_POLICIES_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies?expanded=true"
DOMAINS_ENDPOINT = "/api/fmc_platform/v1/info/domain"
NETWORKS_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/object/networks?expanded=true"
NETWORK_GROUPS_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups?expanded=true"
PORTS_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/object/ports?expanded=true"
PORT_GROUPS_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/object/portobjectgroups?expanded=true"
UNUSED_NETWORKS_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/object/networks?filter=%22unusedOnly%3Atrue%22&expanded=false"
UNUSED_HOST_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/object/hosts?filter=%22unusedOnly%3Atrue%22&expanded=false"
UNUSED_NETGRP_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups?filter=%22unusedOnly%3Atrue%22&expanded=false"
UNUSED_PORTS_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/object/ports?filter=%22unusedOnly%3Atrue%22&expanded=false"
UNUSED_PORTGRP_ENDPOINT = "/api/fmc_config/v1/domain/{domainUUID}/object/portobjectgroups?filter=%22unusedOnly%3Atrue%22&expanded=false"

# Specify the name of the Excel file
OUTPUT_FILENAME = 'exported_data.xlsx'

UNUSED_ENDPOINTS = [
    UNUSED_NETWORKS_ENDPOINT,
    UNUSED_HOST_ENDPOINT,
    UNUSED_NETGRP_ENDPOINT,
    UNUSED_PORTS_ENDPOINT,
    UNUSED_PORTGRP_ENDPOINT
]

# Protocol Dictionary
IP_PROTOS = {
    1: 'ICMP',
    2: 'IGMP',
    4: 'IPv4',
    6: 'TCP',
    8: 'EGP',
    9: 'IGP',
    17: 'UDP',
    41: 'IPv6',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    88: 'EIGRP',
    115: 'L2TP'
}

high_risk_ports = {
    '21': 'FTP - File Transfer Protocol (Unencrypted)',
    '22': 'SSH - Secure Shell (Remote Access)',
    '23': 'TELNET - Unencrypted remote login',
    '53': 'DNS - Domain Name System (Can be exploited for DNS tunneling)',
    '80': 'HTTP - Unencrypted web traffic',
    '1080': 'SOCKS - Proxy server',
    '8080': 'HTTP Alternate (Often used for web proxies)',
    '139': 'NetBIOS - Legacy Windows file/printer sharing',
    '445': 'SMB - Windows file sharing over Internet',
    '3389': 'RDP - Remote Desktop Protocol'
}

starting_columns = [
    'ruleIndex', 'name', 'rule_category', 'rule_domain', 'id', 'enabled', 'action', 'rule_szn', 'snet_list',
    'snet_list_bo', 'sport_list', 'sport_bo', 'rule_dzn', 'dnet_list', 'dnet_list_bo', 'dport_list', 'dport_bo',
    'app_list', 'logBegin', 'logEnd'
]

# Disable SSL warnings (not recommended for production)
requests.packages.urllib3.disable_warnings()

headers = {
    "Content-Type": "application/json",
}


def authenticate(url, username, password, headers):
    response = requests.post(
        url + AUTH_ENDPOINT,
        headers=headers,
        auth=requests.auth.HTTPBasicAuth(username, password),
        verify=False
    )

    if response.status_code == 204:
        headers['X-auth-access-token'] = response.headers['X-auth-access-token']
        headers['X-auth-refresh-token'] = response.headers['X-auth-refresh-token']
        domain_uuid = response.headers['DOMAIN_UUID']
        return domain_uuid
    else:
        raise Exception("Failed to authenticate. Status code:", response.status_code)


def get_domain_uuid_for_name(url, headers, desired_name):
    response = requests.get(url + DOMAINS_ENDPOINT, headers=headers, verify=False)

    if response.status_code == 200:
        domains = response.json().get('items', [])
        for domain in domains:
            if domain.get('name') == desired_name:
                return domain.get('uuid')
    else:
        raise Exception("Failed to fetch domains. Status code:", response.status_code)


def get_devices(url, domain_uuid, headers):
    response = requests.get(
        url + DEVICES_ENDPOINT.format(domainUUID=domain_uuid),
        headers=headers,
        verify=False
    )

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception("Failed to fetch devices. Status code:", response.status_code)


def get_unused_objects(url, domain_uuid, headers, endpoint):
    full_url = url + endpoint.format(domainUUID=domain_uuid)
    response = requests.get(full_url, headers=headers, verify=False)

    if response.status_code == 200:
        return response.json().get('items', [])
    else:
        raise Exception(f"Failed to fetch data from {full_url}. Status code: {response.status_code}")


def get_assigned_policy(fmc_url, domain_uuid, headers):
    url = f"{fmc_url}/api/fmc_config/v1/domain/{domain_uuid}/assignment/policyassignments?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()


def get_access_rules(fmc_url, domain_uuid, policy_id, headers):
    url = f"{fmc_url}/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{policy_id}/accessrules?expanded=true"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()


def protocol_name(protocol_number):
    return IP_PROTOS.get(int(protocol_number), "UNKNOWN").upper()


def format_literal(literal):
    proto = protocol_name(literal['protocol'])

    if 'port' in literal:
        return f"{proto}/{literal['port']}"
    elif 'icmpType' in literal:
        if literal['icmpType'] == 'Any':
            return f"{proto}/Any"
        elif literal['icmpType'] == '8':
            return f"{proto}/Echo"
        else:
            return f"{proto}/{literal['icmpType']}"
    else:
        return proto


def fetch_hitcount_data(fmc_url, policy_id, domain_uuid, device_id, headers):
    """
    Fetch hit count details for a given policy ID.
    """
    url = f'{fmc_url}/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{policy_id}/operational/hitcounts?filter="deviceId:{device_id}"&expanded=true'

    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        data = response.json()
        rule_hitcounts = []

        for item in data.get("items", []):
            rule_detail = {
                "rule_id": item.get("rule", {}).get("id"),
                "rule_name": item.get("rule", {}).get("name"),
                "hit_count": item.get("hitCount", 0),
                "first_hit": item.get("firstHitTimeStamp", "N/A"),
                "last_hit": item.get("lastHitTimeStamp", "N/A")
            }
            rule_hitcounts.append(rule_detail)

        return rule_hitcounts

    else:
        print(f"Failed to retrieve data for policy ID: {policy_id}. Status Code: {response.status_code}")
        return []


def get_networks_and_network_groups(url, domain_uuid, headers):
    # Fetch networks
    response_networks = requests.get(
        url + NETWORKS_ENDPOINT.format(domainUUID=domain_uuid),
        headers=headers,
        verify=False
    )
    networks = response_networks.json().get('items', []) if response_networks.status_code == 200 else []

    # Fetch network groups
    response_network_groups = requests.get(
        url + NETWORK_GROUPS_ENDPOINT.format(domainUUID=domain_uuid),
        headers=headers,
        verify=False
    )
    network_groups = response_network_groups.json().get('items', []) if response_network_groups.status_code == 200 else []

    return networks, network_groups


def get_ports_and_port_groups(url, domain_uuid, headers):
    # Fetch port objects
    response_ports = requests.get(
        url + PORTS_ENDPOINT.format(domainUUID=domain_uuid),
        headers=headers,
        verify=False
    )
    ports = response_ports.json().get('items', []) if response_ports.status_code == 200 else []

    # Fetch port object groups
    response_port_groups = requests.get(
        url + PORT_GROUPS_ENDPOINT.format(domainUUID=domain_uuid),
        headers=headers,
        verify=False
    )
    port_groups = response_port_groups.json().get('items', []) if response_port_groups.status_code == 200 else []

    return ports, port_groups


def update_ports(port_grp_str):
    ports = []
    for name in port_grp_str.split('; '):
        if name in port_lookup:
            ports.append(port_lookup[name])
        elif name in port_group_lookup:
            ports.extend(port_group_lookup[name].split('; '))
    return '; '.join(ports)


def update_net(net):
    # Check if snet is empty or NaN. If so, return the original value
    if pd.isna(net) or not net:
        return net

    # Search in the df_networks DataFrame
    if net in df_networks['name'].values:
        return df_networks[df_networks['name'] == net]['value'].iloc[0]

    # Search in the df_network_groups DataFrame
    if net in df_network_groups['name'].values:
        return df_network_groups[df_network_groups['name'] == net]['net_list_grp'].iloc[0]

    # If snet is not found in both DataFrames, return the original value
    return net


def generate_findings(row):
    findings = []

    # Checking high-risk ports for sport_list
    sport_bo_list = row['sport_bo'].split(';')  # Splitting the string on semicolon to get individual port entries
    for port_entry in sport_bo_list:
        port_num = port_entry.split('/')[0].strip()  # Splitting on slash and taking the first part (the port number)
        if port_num in high_risk_ports.keys():  # Making sure we're checking against keys
            findings.append(f"Source port {port_num} is high risk: {high_risk_ports[port_num]}")

    # Checking high-risk ports for dport_list
    dport_bo_list = row['dport_bo'].split(';')
    for port_entry in dport_bo_list:
        port_num = port_entry.split('/')[0].strip()
        if port_num in high_risk_ports.keys():
            findings.append(f"Destination port {port_num} is high risk: {high_risk_ports[port_num]}")

    # Check for 'sport' and 'dport' being 'any':
    if row['sport_list'] == 'any' and row['dport_list'] == 'any':
        findings.append('Both Source and Destination ports are set to "any".')

    # Check for 'dnet_list_bo' and 'snet_list_bo' being 'any':
    if row['dnet_list_bo'] == 'any' and row['snet_list_bo'] == 'any':
        findings.append('Both Source and Destination network objects are set to "any".')

    # Check for 'rule_szn' and 'rule_dzn' being 'any':
    if row['rule_szn'] == 'any' and row['rule_dzn'] == 'any':
        findings.append('Both Source and Destination zones are set to "any".')

    return '; '.join(findings)


def check_most_recent_hit(row):
    most_recent_hit = max([row[col] for col in hit_columns if pd.notnull(row[col])], default=None)
    if most_recent_hit is None:
        return 'Rule has never been hit.'
    days_since_most_recent = (pd.Timestamp.now() - most_recent_hit).days
    if days_since_most_recent > 30:
        return f"Rule hasn't been hit for {days_since_most_recent} days."
    else:
        return ''  # Ignore if less than 30 days


def check_ip_overlap(ip1_list, ip2_list):
    for ip1 in ip1_list:
        for ip2 in ip2_list:
            if ip_network(ip1).overlaps(ip_network(ip2)):
                return True
    return False


def check_port_overlap(port1_bo, port2_bo):
    port1_numbers = [port.split('/')[0].strip() for port in port1_bo.split(';')]
    port2_numbers = [port.split('/')[0].strip() for port in port2_bo.split(';')]

    for port1 in port1_numbers:
        for port2 in port2_numbers:
            if 'any' in port1 or 'any' in port2 or port1 == port2:
                return True
    return False


def find_shadow_rules(df_rules, ignore_rule_names=[]):
    shadow_rules = []

    # Reverse the dataframe so we start with the bottom rules
    df_rules_rev = df_rules[::-1]

    for index, current_rule in df_rules_rev.iterrows():

        # Continue to the next iteration if current rule's name is in the ignore list
        if current_rule['name'] in ignore_rule_names:
            continue

        for prev_index, prev_rule in df_rules_rev[df_rules_rev['ruleIndex'] < current_rule['ruleIndex']].iterrows():

            # Continue to the next iteration if previous rule's name is in the ignore list
            if prev_rule['name'] in ignore_rule_names:
                continue

            if check_port_overlap(current_rule['sport_bo'], prev_rule['sport_bo']) and \
                    check_port_overlap(current_rule['dport_bo'], prev_rule['dport_bo']) and \
                    ('any' in [current_rule['snet_list_bo'], prev_rule['snet_list_bo']] or \
                     set(current_rule['snet_list_bo'].split(';')).intersection(
                         set(prev_rule['snet_list_bo'].split(';')))) and \
                    ('any' in [current_rule['dnet_list_bo'], prev_rule['dnet_list_bo']] or \
                     set(current_rule['dnet_list_bo'].split(';')).intersection(
                         set(prev_rule['dnet_list_bo'].split(';')))):
                shadow_rules.append((current_rule['ruleIndex'], prev_rule['ruleIndex']))

    return shadow_rules


def convert_to_readable_df(df_rules, shadowed_pairs):
    # Convert shadowed pairs into a list of dictionaries with readable rule names
    readable_pairs = []
    for curr_idx, prev_idx in shadowed_pairs:
        curr_name = df_rules[df_rules['ruleIndex'] == curr_idx]['name'].iloc[0]
        prev_name = df_rules[df_rules['ruleIndex'] == prev_idx]['name'].iloc[0]
        readable_pairs.append({
            'Current Rule ID': curr_idx,
            'Current Rule Name': curr_name,
            'Shadowed By Rule ID': prev_idx,
            'Shadowed By Rule Name': prev_name
        })

    # Convert the list of dictionaries into a DataFrame
    df_readable = pd.DataFrame(readable_pairs)

    return df_readable


if __name__ == '__main__':
    df_rules = pd.DataFrame(columns=starting_columns)
    authenticate(FMC_URL, USERNAME, PASSWORD, headers)  # This sets up headers with the required tokens
    domain_uuid = get_domain_uuid_for_name(FMC_URL, headers, DOMAIN)

    devices_data = get_devices(FMC_URL, domain_uuid, headers)
    df_devices = pd.DataFrame(devices_data['items'])

    unused_data = []

    for endpoint in UNUSED_ENDPOINTS:
        unused_data.extend(get_unused_objects(FMC_URL, domain_uuid, headers, endpoint))

    df_unused_net_objects = pd.DataFrame(unused_data)
    df_unused_net_objects = df_unused_net_objects[['name', 'type', 'id']]

    # Extract the nested deviceSerialNumber
    df_devices['deviceSerialNumber'] = df_devices['metadata'].apply(lambda x: x.get('deviceSerialNumber'))

    # Filter columns of interest for devices
    df_devices = df_devices[['name', 'deviceSerialNumber', 'id', 'model', 'healthStatus', 'sw_version']]

    assigned_policy_data = get_assigned_policy(FMC_URL, domain_uuid, headers)
    policy_id = assigned_policy_data['items'][0]['policy']['id']

    access_rules_data = get_access_rules(FMC_URL, domain_uuid, policy_id, headers)

    df_temp = pd.DataFrame(access_rules_data['items'])
    df_rules = pd.concat([df_rules, df_temp], ignore_index=True)

    # Fetch networks and network groups
    networks, network_groups = get_networks_and_network_groups(FMC_URL, domain_uuid, headers)

    # Convert to dataframes if you need
    df_networks = pd.DataFrame(networks)
    df_network_groups = pd.DataFrame(network_groups)
    df_network_groups['net_list_grp'] = df_network_groups['literals'].apply(
        lambda x: '; '.join([item['value'] for item in x]) if isinstance(x, list) else '')

    ports, port_groups = get_ports_and_port_groups(FMC_URL, domain_uuid, headers)
    df_ports = pd.DataFrame(ports)
    df_port_groups = pd.DataFrame(port_groups)
    df_port_groups['ports'] = df_port_groups['objects'].apply(
        lambda x: '; '.join([f"{item['port']}/{item['name']}" for item in x]) if isinstance(x, list) else ''
    )

    # Create a lookup dictionary for individual ports
    port_lookup = dict(zip(df_ports['name'], df_ports['port'] + '/' + df_ports['protocol']))

    # Create a lookup dictionary for port groups
    port_group_lookup = dict(zip(df_port_groups['name'], df_port_groups['ports']))

    # Extract the nested rule data
    df_rules['ruleIndex'] = df_rules['metadata'].apply(lambda x: x.get('ruleIndex'))
    df_rules['rule_category'] = df_rules['metadata'].apply(lambda x: x.get('category'))
    df_rules['rule_domain'] = df_rules['metadata'].apply(lambda x: x['domain'].get('name'))
    if 'sourceZones' in df_rules.columns:
        df_rules['rule_szn'] = df_rules['sourceZones'].apply(
            lambda x: '; '.join([item['name'] for item in x['objects']]) if isinstance(x, dict) else '')
    if 'destinationZones' in df_rules.columns:
        df_rules['rule_dzn'] = df_rules['destinationZones'].apply(
            lambda x: '; '.join([item['name'] for item in x['objects']]) if isinstance(x, dict) else '')
    if 'sourceNetworks' in df_rules.columns:
        df_rules['snet_list'] = df_rules['sourceNetworks'].apply(
            lambda x: '; '.join([item['name'] for item in x['objects']]) if isinstance(x, dict) else '')
    if 'destinationNetworks' in df_rules.columns:
        df_rules['dnet_list'] = df_rules['destinationNetworks'].apply(
            lambda x: '; '.join([item['name'] for item in x['objects']]) if isinstance(x, dict) else '')
    if 'applications' in df_rules.columns:
        df_rules['app_list'] = df_rules['applications'].apply(
            lambda x: '; '.join([item['name'] for item in x['applications']]) if isinstance(x,
                                                                                            dict) and 'applications' in x else '')
    if 'destinationPorts' in df_rules.columns:
        df_rules['dport_list'] = df_rules['destinationPorts'].apply(
            lambda x: '; '.join([format_literal(literal) for literal in x['literals']]) if isinstance(x, dict)
                                                                                           and 'literals' in x else '')
        df_rules['dport_list'] = df_rules['destinationPorts'].apply(
            lambda x: '; '.join([item['name'] for item in x.get('objects', [])]) if isinstance(x, dict) else ''
        )
    if 'sourcePorts' in df_rules.columns:
        df_rules['sport_list'] = df_rules['sourcePorts'].apply(
            lambda x: '; '.join([format_literal(literal) for literal in x['literals']]) if isinstance(x, dict)
                                                                                           and 'literals' in x else '')
        df_rules['sport_list'] = df_rules['sourcePorts'].apply(
            lambda x: '; '.join([item['name'] for item in x.get('objects', [])]) if isinstance(x, dict) else ''
        )

    df_rules['dport_bo'] = df_rules['dport_list'].apply(update_ports)
    df_rules['snet_list_bo'] = df_rules['snet_list'].apply(update_net)
    df_rules['dnet_list_bo'] = df_rules['dnet_list'].apply(update_net)

    columns_of_interest = ['ruleIndex', 'name', 'rule_category', 'rule_domain', 'id', 'enabled', 'action', 'rule_szn',
                           'snet_list', 'snet_list_bo', 'sport_list', 'sport_bo', 'rule_dzn', 'dnet_list',
                           'dnet_list_bo', 'dport_list', 'dport_bo', 'app_list', 'logBegin', 'logEnd']

    # Filter only the columns that actually exist in df_rules
    filtered_columns = [col for col in columns_of_interest if col in df_rules.columns]

    df_rules = df_rules[filtered_columns]

    for device_id in df_devices['id']:
        device_name = df_devices[df_devices['id'] == device_id]['name'].values[0]  # Assuming unique device IDs

        # Fetch the hitcount data for the device
        hitcount_data = fetch_hitcount_data(FMC_URL, policy_id, domain_uuid, device_id,
                                            headers)  # Assuming you have a function like this
        hitcount_df = pd.DataFrame(hitcount_data)

        # Create a small dataframe to match rule policy numbers and hitcounts
        rule_hitcount_df = hitcount_df[['rule_id', 'rule_name', 'hit_count', 'first_hit', 'last_hit']]
        rule_hitcount_df = rule_hitcount_df.rename(columns={
            'hit_count': f'{device_name}_hit_count',
            'first_hit': f'{device_name}_first_hit',
            'last_hit': f'{device_name}_last_hit'
        })

        # Merge with the main df_rules dataframe on the rule policy numbers
        df_rules = df_rules.merge(rule_hitcount_df[['rule_id', f'{device_name}_hit_count', f'{device_name}_first_hit',
                                                    f'{device_name}_last_hit']],
                                  left_on='id', right_on='rule_id', how='left').drop(columns='rule_id')

    # Fill in "Any" for empty values in rules.
    cols_to_fill = ['rule_szn', 'snet_list', 'snet_list_bo', 'sport_list', 'sport_bo', 'rule_dzn', 'dnet_list',
                    'dnet_list_bo', 'dport_list', 'dport_bo', 'app_list']

    # Fill NaN or blank values with 'any'
    for col in cols_to_fill:
        df_rules[col] = df_rules[col].fillna('any')
        df_rules[col] = df_rules[col].replace('', 'any')

    if 'findings' not in df_rules.columns:
        df_rules['findings'] = ''
    df_rules['findings'] = df_rules.apply(generate_findings, axis=1)

    # Dynamically get columns that contain '_last_hit'
    hit_columns = [col for col in df_rules.columns if '_last_hit' in col]

    # Convert all relevant columns to datetime format
    for col in hit_columns:
        df_rules[col] = pd.to_datetime(df_rules[col], errors='coerce', format='%Y-%m-%dT%H:%M:%SZ')
    df_rules['hit_findings'] = df_rules.apply(check_most_recent_hit, axis=1)

    ignored_rules = ["URL Monitor", "Threat Inspection"]
    shadowed_pairs = find_shadow_rules(df_rules, ignored_rules)
    df_shadow_rules = pd.DataFrame(shadowed_pairs)
    # Convert DataFrames to pretty tables and print
    #print("Devices:")
    #print(tabulate(df_devices, headers='keys', tablefmt='grid'))
    #print("\nAccess Rules:")
    #print(tabulate(df_rules, headers='keys', tablefmt='grid'))
    #print("\nNetworks:")
    df_networks = df_networks[['name', 'value', 'description', 'type', 'id']]
    #print(tabulate(df_networks, headers='keys', tablefmt='grid'))
    #print("\nNetwork Groups:")
    df_network_groups = df_network_groups[['name', 'net_list_grp', 'description', 'type', 'id']]
    #print(tabulate(df_network_groups, headers='keys', tablefmt='grid'))
    #print("\nPorts:")
    df_ports = df_ports[['name', 'port', 'protocol', 'description', 'type', 'id']]
    #print(tabulate(df_ports, headers='keys', tablefmt='grid'))
    #print("\nPort Groups:")
    df_port_groups = df_port_groups[['name', 'ports', 'description', 'type', 'id']]
    #print(tabulate(df_port_groups, headers='keys', tablefmt='grid'))
    #print("\nUnused Objects:")
    #print(tabulate(df_unused_net_objects, headers='keys', tablefmt='grid'))
    df_shadowed_readable = convert_to_readable_df(df_rules, shadowed_pairs)
    #print(tabulate(df_shadowed_readable, headers='keys', tablefmt='grid'))

    with pd.ExcelWriter(OUTPUT_FILENAME) as writer:
        df_devices.to_excel(writer, sheet_name='Devices', index=False)
        df_rules.to_excel(writer, sheet_name='Rules', index=False)
        df_networks.to_excel(writer, sheet_name='Networks', index=False)
        df_network_groups.to_excel(writer, sheet_name='Network Groups', index=False)
        df_ports.to_excel(writer, sheet_name='Ports', index=False)
        df_port_groups.to_excel(writer, sheet_name='Port Groups', index=False)
        df_unused_net_objects.to_excel(writer, sheet_name='Unused Net Objects', index=False)
        df_shadowed_readable.to_excel(writer, sheet_name='Shadowed Rules', index=False)

        # Adjust columns for each sheet
        for sheet_name in writer.sheets:
            worksheet = writer.sheets[sheet_name]
            for col in worksheet.columns:
                max_length = 0
                column = col[0].column_letter  # Get the column name (A, B, C, ...)
                for cell in col:
                    try:  # Necessary to avoid error on empty cells
                        if len(str(cell.value)) > max_length:
                            max_length = len(cell.value)
                    except:
                        pass
                adjusted_width = (max_length + 2)  # add a little extra space
                worksheet.column_dimensions[column].width = adjusted_width

    print(f"Data exported to {OUTPUT_FILENAME}")
