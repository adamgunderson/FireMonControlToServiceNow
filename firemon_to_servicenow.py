#!/usr/bin/env python3
# File: firemon_to_servicenow.py
# Description: Script to send FireMon control failures to ServiceNow

import sys
import os
import glob

# Dynamically add FireMon package paths based on available Python versions
# This supports Python 3.8 through 3.12+ on FireMon OS
firemon_base_path = '/usr/lib/firemon/devpackfw/lib'

# Check if FireMon package directory exists
if os.path.exists(firemon_base_path):
    # Find all pythonX.Y directories and sort them in reverse order (newest first)
    python_dirs = glob.glob(os.path.join(firemon_base_path, 'python3.*'))
    python_dirs.sort(reverse=True)

    # Add all found paths to sys.path (prioritize newer versions)
    for python_dir in python_dirs:
        site_packages = os.path.join(python_dir, 'site-packages')
        if os.path.exists(site_packages) and site_packages not in sys.path:
            sys.path.insert(0, site_packages)

# Try to import requests
try:
    import requests
except ImportError:
    # If still failing, import without FireMon paths (for non-FireMon systems)
    import requests

import argparse
import json
import logging
from urllib.parse import quote
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Severity level mapping (in order from lowest to highest)
SEVERITY_LEVELS = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5
}

# ============================================================================
# FireMon API Functions
# ============================================================================

def get_firemon_session(base_url, username, password, verify_ssl=True):
    """
    Create an authenticated session with FireMon API

    Args:
        base_url (str): Base URL for FireMon API
        username (str): Username for authentication
        password (str): Password for authentication
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        requests.Session: Authenticated session or None
    """
    api_url = f"{base_url}/securitymanager/api"

    session = requests.Session()
    session.auth = (username, password)
    session.headers = {'Content-Type': 'application/json', 'accept': 'application/json'}

    logon_data = {
        "username": username,
        "password": password
    }

    try:
        logger.info(f"Authenticating to FireMon at {api_url}/authentication/validate")
        response = session.post(
            f'{api_url}/authentication/validate',
            data=json.dumps(logon_data),
            verify=verify_ssl
        )

        if response.status_code != 200:
            logger.error(f"FireMon authentication failed with status code: {response.status_code}")
            return None

        auth_data = response.json()
        if auth_data.get('authStatus') != 'AUTHORIZED':
            logger.error(f"FireMon authentication failed: {auth_data.get('authStatus')}")
            return None

        logger.info(f"Successfully authenticated to FireMon as {username}")
        return session

    except requests.exceptions.RequestException as e:
        logger.error(f"Error during FireMon authentication: {e}")
        return None

def get_failed_rules(base_url, session, device_id, assessment_uuid, verify_ssl=True, page_size=100):
    """
    Get list of rules with failed controls for specific device and assessment

    Args:
        base_url (str): Base URL for FireMon API
        session (requests.Session): Authenticated session
        device_id (int): Device ID
        assessment_uuid (str): Assessment UUID
        verify_ssl (bool): Whether to verify SSL certificates
        page_size (int): Page size for pagination

    Returns:
        list: List of rules with failed controls
    """
    query = f"domain{{id=1}} and device{{id={device_id}}} and assessment{{id='{assessment_uuid}'}} and control{{status='FAIL'}}"
    encoded_query = quote(query)

    url = f"{base_url}/securitymanager/api/siql/secrule/paged-search?q={encoded_query}&page=0&pageSize={page_size}"

    try:
        all_results = []
        response = session.get(url, verify=verify_ssl)

        if response.status_code != 200:
            logger.error(f"Failed to get rules. Status code: {response.status_code}")
            return []

        data = response.json()
        total_results = data.get("total", 0)
        all_results.extend(data.get("results", []))

        # Handle pagination
        if total_results > page_size:
            total_pages = (total_results + page_size - 1) // page_size
            logger.info(f"Found {total_results} results, retrieving {total_pages} pages")

            for page_num in range(1, total_pages):
                page_url = f"{base_url}/securitymanager/api/siql/secrule/paged-search?q={encoded_query}&page={page_num}&pageSize={page_size}"
                page_response = session.get(page_url, verify=verify_ssl)

                if page_response.status_code == 200:
                    page_data = page_response.json()
                    all_results.extend(page_data.get("results", []))

        logger.info(f"Retrieved {len(all_results)} rules with failed controls")
        return all_results

    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting failed rules: {e}")
        return []

def get_rule_control_violations(base_url, session, device_id, assessment_uuid, rule_uid, verify_ssl=True, page_size=100):
    """
    Get control violations for a specific rule

    Args:
        base_url (str): Base URL for FireMon API
        session (requests.Session): Authenticated session
        device_id (int): Device ID
        assessment_uuid (str): Assessment UUID
        rule_uid (str): Rule UID
        verify_ssl (bool): Whether to verify SSL certificates
        page_size (int): Page size for pagination

    Returns:
        list: List of control violations for the rule
    """
    query = f"device {{ id = {device_id} }} AND assessment {{ id = '{assessment_uuid}' }} AND control {{ status = 'FAIL' }} AND rule {{ uid = '{rule_uid}' }}"
    encoded_query = quote(query)

    url = f"{base_url}/securitymanager/api/siql/control/paged-search?q={encoded_query}&page=0&pageSize={page_size}"

    try:
        all_results = []
        response = session.get(url, verify=verify_ssl)

        if response.status_code != 200:
            logger.error(f"Failed to get control violations. Status code: {response.status_code}")
            return []

        data = response.json()
        total_results = data.get("total", 0)
        all_results.extend(data.get("results", []))

        # Handle pagination
        if total_results > page_size:
            total_pages = (total_results + page_size - 1) // page_size

            for page_num in range(1, total_pages):
                page_url = f"{base_url}/securitymanager/api/siql/control/paged-search?q={encoded_query}&page={page_num}&pageSize={page_size}"
                page_response = session.get(page_url, verify=verify_ssl)

                if page_response.status_code == 200:
                    page_data = page_response.json()
                    all_results.extend(page_data.get("results", []))

        return all_results

    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting control violations: {e}")
        return []

def get_device_level_control_failures(base_url, session, device_id, assessment_uuid, verify_ssl=True, page_size=100):
    """
    Get device-level control failures (not tied to specific rules)
    This includes Device Property, Regex Config, and other device-level checks

    Args:
        base_url (str): Base URL for FireMon API
        session (requests.Session): Authenticated session
        device_id (int): Device ID
        assessment_uuid (str): Assessment UUID
        verify_ssl (bool): Whether to verify SSL certificates
        page_size (int): Page size for pagination

    Returns:
        list: List of device-level control failures
    """
    # Query for failed controls on this device/assessment without rule association
    query = f"device {{ id = {device_id} }} AND assessment {{ id = '{assessment_uuid}' }} AND control {{ status = 'FAIL' }}"
    encoded_query = quote(query)

    url = f"{base_url}/securitymanager/api/siql/control/paged-search?q={encoded_query}&page=0&pageSize={page_size}"

    try:
        all_results = []
        response = session.get(url, verify=verify_ssl)

        if response.status_code != 200:
            logger.error(f"Failed to get device-level control failures. Status code: {response.status_code}")
            return []

        data = response.json()
        total_results = data.get("total", 0)
        results = data.get("results", [])

        # Filter for device-level controls (those with ruleCount == 0 or controlType != "Rule Search")
        device_level_controls = [
            ctrl for ctrl in results
            if ctrl.get("ruleCount", 0) == 0 or ctrl.get("controlType") != "Rule Search"
        ]
        all_results.extend(device_level_controls)

        # Handle pagination
        if total_results > page_size:
            total_pages = (total_results + page_size - 1) // page_size

            for page_num in range(1, total_pages):
                page_url = f"{base_url}/securitymanager/api/siql/control/paged-search?q={encoded_query}&page={page_num}&pageSize={page_size}"
                page_response = session.get(page_url, verify=verify_ssl)

                if page_response.status_code == 200:
                    page_data = page_response.json()
                    page_results = page_data.get("results", [])
                    device_level_controls = [
                        ctrl for ctrl in page_results
                        if ctrl.get("ruleCount", 0) == 0 or ctrl.get("controlType") != "Rule Search"
                    ]
                    all_results.extend(device_level_controls)

        logger.info(f"Found {len(all_results)} device-level control failures for device {device_id}")
        return all_results

    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting device-level control failures: {e}")
        return []

def get_device_group_devices(base_url, session, device_group_id, verify_ssl=True):
    """
    Get all devices in a device group

    Args:
        base_url (str): Base URL for FireMon API
        session (requests.Session): Authenticated session
        device_group_id (int): Device group ID
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        list: List of device IDs in the group
    """
    url = f"{base_url}/securitymanager/api/domain/1/devicegroup/{device_group_id}"

    try:
        response = session.get(url, verify=verify_ssl)

        if response.status_code != 200:
            logger.error(f"Failed to get device group. Status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return []

        data = response.json()
        devices = data.get("devices", [])
        device_ids = [device.get("id") for device in devices if device.get("id")]

        logger.info(f"Found {len(device_ids)} devices in device group {device_group_id}")
        return device_ids

    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting device group: {e}")
        return []

def get_all_devices(base_url, session, verify_ssl=True):
    """
    Get all devices in the domain

    Args:
        base_url (str): Base URL for FireMon API
        session (requests.Session): Authenticated session
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        list: List of device IDs
    """
    url = f"{base_url}/securitymanager/api/domain/1/device"

    try:
        response = session.get(url, verify=verify_ssl)

        if response.status_code != 200:
            logger.error(f"Failed to get devices. Status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return []

        data = response.json()
        device_ids = [device.get("id") for device in data if device.get("id")]

        logger.info(f"Found {len(device_ids)} total devices in domain")
        return device_ids

    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting devices: {e}")
        return []

def get_device_name(base_url, session, device_id, verify_ssl=True):
    """
    Get device name from FireMon API

    Args:
        base_url (str): Base URL for FireMon API
        session (requests.Session): Authenticated session
        device_id (int): Device ID
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        str: Device name or fallback string
    """
    url = f"{base_url}/securitymanager/api/domain/1/device/{device_id}"

    try:
        response = session.get(url, verify=verify_ssl)

        if response.status_code == 200:
            data = response.json()
            device_name = data.get("name", f"Device-{device_id}")
            logger.debug(f"Retrieved device name: {device_name} for device ID {device_id}")
            return device_name
        else:
            logger.warning(f"Failed to get device name for ID {device_id}. Status: {response.status_code}")
            return f"Device-{device_id}"

    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting device name: {e}")
        return f"Device-{device_id}"

# ============================================================================
# ServiceNow API Functions
# ============================================================================

def get_servicenow_session(instance_url, username, password, verify_ssl=True):
    """
    Create a session for ServiceNow API

    Args:
        instance_url (str): ServiceNow instance URL (e.g., https://instance.service-now.com)
        username (str): ServiceNow username
        password (str): ServiceNow password
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        requests.Session: Configured session
    """
    session = requests.Session()
    session.auth = (username, password)
    session.headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    logger.info(f"Created ServiceNow session for {instance_url}")
    return session

def check_existing_record(session, instance_url, table_name, unique_identifier, verify_ssl=True):
    """
    Check if a record already exists in ServiceNow based on a unique identifier

    Args:
        session (requests.Session): ServiceNow session
        instance_url (str): ServiceNow instance URL
        table_name (str): Table name to search
        unique_identifier (str): Unique identifier to search for (e.g., control failure ID)
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        dict: Existing record if found, None otherwise
    """
    url = f"{instance_url}/api/now/table/{table_name}"

    # Use appropriate field for deduplication based on table type
    if table_name == "em_event":
        query_field = "message_key"
    elif table_name.startswith("u_"):
        query_field = "u_correlation_id"
    else:
        query_field = "correlation_id"

    params = {
        'sysparm_query': f'{query_field}={unique_identifier}',
        'sysparm_limit': 1
    }

    try:
        logger.debug(f"Checking for existing record: {url} with query {query_field}={unique_identifier}")
        response = session.get(url, params=params, verify=verify_ssl)
        logger.debug(f"ServiceNow response status: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            results = data.get('result', [])
            logger.debug(f"ServiceNow returned {len(results)} result(s)")
            if results:
                # Verify the correlation_id actually matches (not just any record returned)
                returned_correlation = results[0].get(query_field, '')
                if returned_correlation == unique_identifier:
                    logger.debug(f"Found existing record for {unique_identifier}")
                    return results[0]
                else:
                    logger.debug(f"Record found but {query_field} doesn't match: '{returned_correlation}' != '{unique_identifier}'")
                    return None

        return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Error checking for existing record: {e}")
        return None

def create_servicenow_record(session, instance_url, table_name, record_data, verify_ssl=True):
    """
    Create a record in ServiceNow

    Args:
        session (requests.Session): ServiceNow session
        instance_url (str): ServiceNow instance URL
        table_name (str): Table name to create record in
        record_data (dict): Record data to create
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        dict: Created record or None
    """
    url = f"{instance_url}/api/now/table/{table_name}"

    try:
        response = session.post(url, data=json.dumps(record_data), verify=verify_ssl)

        if response.status_code == 201:
            logger.info(f"Successfully created record in {table_name}")
            return response.json().get('result')
        else:
            logger.error(f"Failed to create record. Status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating ServiceNow record: {e}")
        return None

def update_servicenow_record(session, instance_url, table_name, sys_id, record_data, verify_ssl=True):
    """
    Update an existing record in ServiceNow

    Args:
        session (requests.Session): ServiceNow session
        instance_url (str): ServiceNow instance URL
        table_name (str): Table name
        sys_id (str): System ID of the record to update
        record_data (dict): Updated record data
        verify_ssl (bool): Whether to verify SSL certificates

    Returns:
        dict: Updated record or None
    """
    url = f"{instance_url}/api/now/table/{table_name}/{sys_id}"

    try:
        response = session.patch(url, data=json.dumps(record_data), verify=verify_ssl)

        if response.status_code == 200:
            logger.info(f"Successfully updated record {sys_id} in {table_name}")
            return response.json().get('result')
        else:
            logger.error(f"Failed to update record. Status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Error updating ServiceNow record: {e}")
        return None

# ============================================================================
# Data Formatting Functions
# ============================================================================

def format_network_objects(objects):
    """Format network objects into a readable string"""
    if not objects:
        return "Any"

    result = []
    for obj in objects:
        display_name = obj.get("displayName", "")
        addresses = obj.get("addresses", [])

        if addresses:
            address_values = [addr.get("address") for addr in addresses if addr.get("address")]
            if address_values:
                result.append(f"{display_name} ({', '.join(address_values)})")
            else:
                result.append(display_name)
        else:
            result.append(display_name)

    return ", ".join(result) if result else "Any"

def format_service_objects(objects):
    """Format service objects into a readable string"""
    if not objects:
        return "Any"

    result = []
    for obj in objects:
        display_name = obj.get("displayName", "")
        services = obj.get("services", [])

        if services:
            service_values = []
            for svc in services:
                if svc.get("formattedValue"):
                    service_values.append(svc.get("formattedValue"))
                elif svc.get("protocol") is not None and svc.get("startPort") is not None:
                    protocol = "tcp" if svc.get("protocol") == 6 else "udp" if svc.get("protocol") == 17 else str(svc.get("protocol"))
                    ports = str(svc.get("startPort"))
                    if svc.get("endPort") and svc.get("endPort") != svc.get("startPort"):
                        ports += f"-{svc.get('endPort')}"
                    service_values.append(f"{protocol}/{ports}")

            if service_values:
                result.append(f"{display_name} ({', '.join(service_values)})")
            else:
                result.append(display_name)
        else:
            result.append(display_name)

    return ", ".join(result) if result else "Any"

def create_servicenow_payload_device_level(control, device_id, device_name, assessment_uuid, table_name="incident"):
    """
    Create ServiceNow record payload from FireMon device-level control failure

    Args:
        control (dict): FireMon control violation data
        device_id (int): Device ID
        device_name (str): Device name
        assessment_uuid (str): Assessment UUID
        table_name (str): ServiceNow table name (default: incident)

    Returns:
        dict: ServiceNow record payload
    """
    control_name = control.get("name", "")
    control_description = control.get("description", "")
    control_severity = control.get("severity", "")
    control_code = control.get("code", "")
    control_type = control.get("controlType", "Device Property")

    # Create unique identifier for deduplication (no rule UID for device-level controls)
    correlation_id = f"FM-{device_id}-{assessment_uuid}-DEVICE-{control_code}"

    # Build description with all details
    description = f"""FireMon Security Manager Device-Level Control Failure

Assessment: {assessment_uuid}
Device ID: {device_id}
Device Name: {device_name}

Control Violation:
- Control: {control_name}
- Code: {control_code}
- Type: {control_type}
- Severity: {control_severity}
- Description: {control_description}
"""

    # Map FireMon severity to ServiceNow severity (1-5 scale)
    severity_map = {
        "CRITICAL": "1",
        "HIGH": "2",
        "MEDIUM": "3",
        "LOW": "4",
        "INFO": "5"
    }

    # Handle numeric severity (convert to string first)
    severity_str = str(control_severity).upper()
    severity_value = severity_map.get(severity_str, "3")

    # Create payload based on table type
    if table_name == "em_event":
        # Event Management table schema
        payload = {
            "source": "FireMon Security Manager",
            "node": device_name,
            "type": "Device Control Failure",
            "severity": severity_value,
            "description": description,
            "message_key": correlation_id,
            "resource": f"Device {device_id}",
            "additional_info": f"Control: {control_name}, Code: {control_code}, Type: {control_type}",
            "time_of_event": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }
    elif table_name.startswith("u_"):
        # Custom table schema (u_ prefixed fields)
        payload = {
            "u_short_description": f"FireMon Device Control Failure: {control_name} - {device_name}",
            "u_description": description,
            "u_correlation_id": correlation_id,
            "u_firemon_device_id": str(device_id),
            "u_firemon_device_name": device_name,
            "u_firemon_assessment": assessment_uuid,
            "u_firemon_control_code": control_code,
            "u_firemon_control_type": control_type,
            "u_firemon_severity": severity_str
        }
    else:
        # Incident table schema (default)
        payload = {
            "short_description": f"FireMon Device Control Failure: {control_name} - {device_name}",
            "description": description,
            "correlation_id": correlation_id,
            "impact": severity_value,
            "urgency": severity_value,
            "category": "Security",
            "subcategory": "Firewall Configuration Violation",
            "u_firemon_device_id": str(device_id),
            "u_firemon_assessment": assessment_uuid,
            "u_firemon_control_code": control_code,
            "u_firemon_control_type": control_type,
            "u_firemon_severity": severity_str
        }

    return payload

def create_servicenow_payload(rule, control, device_id, device_name, assessment_uuid, table_name="incident"):
    """
    Create ServiceNow record payload from FireMon rule and control data

    Args:
        rule (dict): FireMon rule data
        control (dict): FireMon control violation data
        device_id (int): Device ID
        device_name (str): Device name from FireMon API
        assessment_uuid (str): Assessment UUID
        table_name (str): ServiceNow table name (default: incident)

    Returns:
        dict: ServiceNow record payload
    """
    rule_name = rule.get("ruleName", "")
    rule_number = rule.get("ruleNumber", "")
    rule_severity = rule.get("cumulativeRuleSeverity", "")
    policy_name = rule.get("policy", {}).get("displayName", "")

    sources = format_network_objects(rule.get("sources", []))
    destinations = format_network_objects(rule.get("destinations", []))
    services = format_service_objects(rule.get("services", []))
    action = rule.get("ruleAction", "")

    control_name = control.get("name", "")
    control_description = control.get("description", "")
    control_severity = control.get("severity", "")
    control_code = control.get("code", "")

    # Create unique identifier for deduplication
    rule_uid = rule.get("matchId", "")
    correlation_id = f"FM-{device_id}-{assessment_uuid}-{rule_uid}-{control_code}"

    # Build description with all details
    description = f"""FireMon Security Manager Rule-Level Control Failure

Assessment: {assessment_uuid}
Device ID: {device_id}

Rule Information:
- Rule Name: {rule_name}
- Rule Number: {rule_number}
- Policy: {policy_name}
- Severity: {rule_severity}
- Action: {action}

Rule Details:
- Sources: {sources}
- Destinations: {destinations}
- Services: {services}

Control Violation:
- Control: {control_name}
- Code: {control_code}
- Severity: {control_severity}
- Description: {control_description}
"""

    # Map FireMon severity to ServiceNow severity (1-5 scale)
    severity_map = {
        "CRITICAL": "1",
        "HIGH": "2",
        "MEDIUM": "3",
        "LOW": "4",
        "INFO": "5"
    }

    # Handle numeric severity (convert to string first)
    severity_str = str(control_severity).upper()
    severity_value = severity_map.get(severity_str, "3")

    # Create payload based on table type
    if table_name == "em_event":
        # Event Management table schema
        payload = {
            "source": "FireMon Security Manager",
            "node": device_name,
            "type": "Rule Control Failure",
            "severity": severity_value,
            "description": description,
            "message_key": correlation_id,
            "resource": f"Rule {rule_number} - {policy_name}",
            "additional_info": f"Control: {control_name}, Code: {control_code}, Rule: {rule_name}",
            "time_of_event": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }
    elif table_name.startswith("u_"):
        # Custom table schema (u_ prefixed fields)
        payload = {
            "u_short_description": f"FireMon Control Failure: {control_name} - {rule_name}",
            "u_description": description,
            "u_correlation_id": correlation_id,
            "u_firemon_device_id": str(device_id),
            "u_firemon_device_name": device_name,
            "u_firemon_assessment": assessment_uuid,
            "u_firemon_rule_uid": rule_uid,
            "u_firemon_control_code": control_code,
            "u_firemon_severity": severity_str
        }
    else:
        # Incident table schema (default)
        payload = {
            "short_description": f"FireMon Control Failure: {control_name} - {rule_name}",
            "description": description,
            "correlation_id": correlation_id,
            "impact": severity_value,
            "urgency": severity_value,
            "category": "Security",
            "subcategory": "Firewall Policy Violation",
            "u_firemon_device_id": str(device_id),
            "u_firemon_assessment": assessment_uuid,
            "u_firemon_rule_uid": rule_uid,
            "u_firemon_control_code": control_code,
            "u_firemon_severity": severity_str
        }

    return payload

# ============================================================================
# Main Functions
# ============================================================================

def process_single_device_assessment(firemon_url, fm_session, snow_session, snow_url,
                                     device_id, assessment_uuid, table_name, verify_ssl,
                                     update_existing, min_severity_level, min_severity):
    """
    Process control failures for a single device and assessment

    Args:
        firemon_url (str): FireMon base URL
        fm_session (requests.Session): Authenticated FireMon session
        snow_session (requests.Session): Authenticated ServiceNow session
        snow_url (str): ServiceNow instance URL
        device_id (int): FireMon device ID
        assessment_uuid (str): FireMon assessment UUID
        table_name (str): ServiceNow table name
        verify_ssl (bool): Whether to verify SSL certificates
        update_existing (bool): Whether to update existing records
        min_severity_level (int): Minimum severity level numeric value
        min_severity (str): Minimum severity level name

    Returns:
        dict: Statistics about the operation
    """
    stats = {
        "total_failures": 0,
        "rule_failures": 0,
        "device_failures": 0,
        "created": 0,
        "updated": 0,
        "skipped": 0,
        "filtered": 0,
        "errors": 0
    }

    # Get device name from FireMon API
    device_name = get_device_name(firemon_url, fm_session, device_id, verify_ssl)
    logger.info(f"Processing device: {device_name} (ID: {device_id})")

    # First, process device-level control failures
    logger.info(f"Checking device-level control failures for device {device_id}")
    device_controls = get_device_level_control_failures(firemon_url, fm_session, device_id, assessment_uuid, verify_ssl)

    for control in device_controls:
        stats["total_failures"] += 1
        stats["device_failures"] += 1

        # Check severity level and filter if below minimum
        control_severity = str(control.get("severity", "INFO")).upper()
        # Handle numeric severity values
        if control_severity.isdigit():
            severity_num = int(control_severity)
            if severity_num >= 9:
                control_severity = "CRITICAL"
            elif severity_num >= 7:
                control_severity = "HIGH"
            elif severity_num >= 5:
                control_severity = "MEDIUM"
            elif severity_num >= 3:
                control_severity = "LOW"
            else:
                control_severity = "INFO"

        control_severity_level = SEVERITY_LEVELS.get(control_severity, 1)

        if control_severity_level < min_severity_level:
            logger.debug(f"Filtering device-level control failure with severity {control_severity} (below minimum {min_severity})")
            stats["filtered"] += 1
            continue

        # Create ServiceNow payload for device-level control
        payload = create_servicenow_payload_device_level(control, device_id, device_name, assessment_uuid, table_name)
        # Get the unique identifier (correlation_id or message_key depending on table)
        if table_name == "em_event":
            correlation_id = payload.get("message_key")
        elif table_name.startswith("u_"):
            correlation_id = payload.get("u_correlation_id")
        else:
            correlation_id = payload.get("correlation_id")

        # Check if record already exists
        existing_record = check_existing_record(snow_session, snow_url, table_name, correlation_id, verify_ssl)

        if existing_record:
            if update_existing:
                sys_id = existing_record.get("sys_id")
                result = update_servicenow_record(snow_session, snow_url, table_name, sys_id, payload, verify_ssl)
                if result:
                    stats["updated"] += 1
                else:
                    stats["errors"] += 1
            else:
                logger.info(f"Skipping existing device-level record: {correlation_id}")
                stats["skipped"] += 1
        else:
            result = create_servicenow_record(snow_session, snow_url, table_name, payload, verify_ssl)
            if result:
                stats["created"] += 1
            else:
                stats["errors"] += 1

    # Second, process rule-level control failures
    logger.info(f"Checking rule-level control failures for device {device_id}")
    failed_rules = get_failed_rules(firemon_url, fm_session, device_id, assessment_uuid, verify_ssl)

    if not failed_rules:
        logger.info("No rules with failed controls found")

    # Process each rule and its control violations
    for rule in failed_rules:
        rule_uid = rule.get("matchId")
        if not rule_uid:
            continue

        logger.info(f"Processing rule: {rule.get('ruleName', rule_uid)}")

        # Get control violations for this rule
        control_violations = get_rule_control_violations(
            firemon_url, fm_session, device_id, assessment_uuid, rule_uid, verify_ssl
        )

        for control in control_violations:
            stats["total_failures"] += 1
            stats["rule_failures"] += 1

            # Check severity level and filter if below minimum
            control_severity = str(control.get("severity", "INFO")).upper()
            # Handle numeric severity values
            if control_severity.isdigit():
                severity_num = int(control_severity)
                if severity_num >= 9:
                    control_severity = "CRITICAL"
                elif severity_num >= 7:
                    control_severity = "HIGH"
                elif severity_num >= 5:
                    control_severity = "MEDIUM"
                elif severity_num >= 3:
                    control_severity = "LOW"
                else:
                    control_severity = "INFO"

            control_severity_level = SEVERITY_LEVELS.get(control_severity, 1)

            if control_severity_level < min_severity_level:
                logger.debug(f"Filtering control failure with severity {control_severity} (below minimum {min_severity})")
                stats["filtered"] += 1
                continue

            # Create ServiceNow payload
            payload = create_servicenow_payload(rule, control, device_id, device_name, assessment_uuid, table_name)
            # Get the unique identifier (correlation_id or message_key depending on table)
            if table_name == "em_event":
                correlation_id = payload.get("message_key")
            elif table_name.startswith("u_"):
                correlation_id = payload.get("u_correlation_id")
            else:
                correlation_id = payload.get("correlation_id")

            # Check if record already exists
            existing_record = check_existing_record(snow_session, snow_url, table_name, correlation_id, verify_ssl)

            if existing_record:
                if update_existing:
                    # Update existing record
                    sys_id = existing_record.get("sys_id")
                    result = update_servicenow_record(snow_session, snow_url, table_name, sys_id, payload, verify_ssl)
                    if result:
                        stats["updated"] += 1
                    else:
                        stats["errors"] += 1
                else:
                    logger.info(f"Skipping existing record: {correlation_id}")
                    stats["skipped"] += 1
            else:
                # Create new record
                result = create_servicenow_record(snow_session, snow_url, table_name, payload, verify_ssl)
                if result:
                    stats["created"] += 1
                else:
                    stats["errors"] += 1

    return stats

def process_control_failures(firemon_url, firemon_user, firemon_pass, snow_url, snow_user, snow_pass,
                             device_ids, assessment_uuids, table_name="incident", verify_ssl=True,
                             update_existing=False, min_severity="INFO"):
    """
    Main function to process FireMon control failures and send to ServiceNow
    Supports multiple devices and assessments

    Args:
        firemon_url (str): FireMon base URL
        firemon_user (str): FireMon username
        firemon_pass (str): FireMon password
        snow_url (str): ServiceNow instance URL
        snow_user (str): ServiceNow username
        snow_pass (str): ServiceNow password
        device_ids (list): List of FireMon device IDs
        assessment_uuids (list): List of FireMon assessment UUIDs
        table_name (str): ServiceNow table name
        verify_ssl (bool): Whether to verify SSL certificates
        update_existing (bool): Whether to update existing records
        min_severity (str): Minimum severity level to process (INFO, LOW, MEDIUM, HIGH, CRITICAL)

    Returns:
        dict: Aggregate statistics about the operation
    """
    aggregate_stats = {
        "total_failures": 0,
        "rule_failures": 0,
        "device_failures": 0,
        "created": 0,
        "updated": 0,
        "skipped": 0,
        "filtered": 0,
        "errors": 0,
        "devices_processed": 0,
        "assessments_processed": 0
    }

    # Validate and normalize minimum severity
    min_severity = min_severity.upper()
    if min_severity not in SEVERITY_LEVELS:
        logger.error(f"Invalid minimum severity: {min_severity}. Must be one of: {', '.join(SEVERITY_LEVELS.keys())}")
        return aggregate_stats

    min_severity_level = SEVERITY_LEVELS[min_severity]
    logger.info(f"Filtering control failures with minimum severity: {min_severity}")

    # Authenticate to FireMon
    fm_session = get_firemon_session(firemon_url, firemon_user, firemon_pass, verify_ssl)
    if not fm_session:
        logger.error("Failed to authenticate to FireMon")
        return aggregate_stats

    # Authenticate to ServiceNow
    snow_session = get_servicenow_session(snow_url, snow_user, snow_pass, verify_ssl)

    # Process each device and assessment combination
    for device_id in device_ids:
        logger.info(f"Processing device ID: {device_id}")
        aggregate_stats["devices_processed"] += 1

        for assessment_uuid in assessment_uuids:
            logger.info(f"  Processing assessment: {assessment_uuid}")
            aggregate_stats["assessments_processed"] += 1

            # Process this device/assessment combination
            stats = process_single_device_assessment(
                firemon_url=firemon_url,
                fm_session=fm_session,
                snow_session=snow_session,
                snow_url=snow_url,
                device_id=device_id,
                assessment_uuid=assessment_uuid,
                table_name=table_name,
                verify_ssl=verify_ssl,
                update_existing=update_existing,
                min_severity_level=min_severity_level,
                min_severity=min_severity
            )

            # Aggregate statistics
            aggregate_stats["total_failures"] += stats["total_failures"]
            aggregate_stats["rule_failures"] += stats["rule_failures"]
            aggregate_stats["device_failures"] += stats["device_failures"]
            aggregate_stats["created"] += stats["created"]
            aggregate_stats["updated"] += stats["updated"]
            aggregate_stats["skipped"] += stats["skipped"]
            aggregate_stats["filtered"] += stats["filtered"]
            aggregate_stats["errors"] += stats["errors"]

    return aggregate_stats

def main():
    parser = argparse.ArgumentParser(
        description='Send FireMon control failures to ServiceNow',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single device and assessment
  python firemon_to_servicenow.py \\
    --firemon-url https://firemon.example.com \\
    --firemon-user admin \\
    --firemon-pass password123 \\
    --snow-url https://instance.service-now.com \\
    --snow-user snow_admin \\
    --snow-pass snow_password \\
    --device-id 123 \\
    --assessment abc-123-def-456

  # Multiple devices and assessments
  python firemon_to_servicenow.py \\
    --firemon-url https://firemon.example.com \\
    --firemon-user admin \\
    --firemon-pass password123 \\
    --snow-url https://instance.service-now.com \\
    --snow-user snow_admin \\
    --snow-pass snow_password \\
    --device-id 123 --device-id 456 --device-id 789 \\
    --assessment abc-123 --assessment def-456 --assessment ghi-789

  # Device group with multiple assessments
  python firemon_to_servicenow.py \\
    --firemon-url https://firemon.example.com \\
    --firemon-user admin \\
    --firemon-pass password123 \\
    --snow-url https://instance.service-now.com \\
    --snow-user snow_admin \\
    --snow-pass snow_password \\
    --device-group-id 5 \\
    --assessment abc-123 --assessment def-456

  # All devices with single assessment
  python firemon_to_servicenow.py \\
    --firemon-url https://firemon.example.com \\
    --firemon-user admin \\
    --firemon-pass password123 \\
    --snow-url https://instance.service-now.com \\
    --snow-user snow_admin \\
    --snow-pass snow_password \\
    --all-devices \\
    --assessment abc-123-def-456
        """
    )

    # FireMon arguments
    parser.add_argument('--firemon-url', required=True,
                       help='FireMon base URL (e.g., https://firemon.example.com)')
    parser.add_argument('--firemon-user', required=True,
                       help='FireMon username')
    parser.add_argument('--firemon-pass', required=True,
                       help='FireMon password')

    # Device selection (mutually exclusive)
    device_group = parser.add_mutually_exclusive_group(required=True)
    device_group.add_argument('--device-id', type=int, action='append',
                             help='FireMon device ID (can be specified multiple times)')
    device_group.add_argument('--device-group-id', type=int,
                             help='FireMon device group ID (processes all devices in group)')
    device_group.add_argument('--all-devices', action='store_true',
                             help='Process all devices in the domain')

    # Assessment selection
    parser.add_argument('--assessment', action='append', required=True,
                       help='FireMon assessment UUID (can be specified multiple times)')

    # ServiceNow arguments
    parser.add_argument('--snow-url', required=True,
                       help='ServiceNow instance URL (e.g., https://instance.service-now.com)')
    parser.add_argument('--snow-user', required=True,
                       help='ServiceNow username')
    parser.add_argument('--snow-pass', required=True,
                       help='ServiceNow password')
    parser.add_argument('--snow-table', default='incident',
                       help='ServiceNow table name (default: incident)')

    # Options
    parser.add_argument('--min-severity', default='INFO',
                       choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                       help='Minimum severity level to process (default: INFO)')
    parser.add_argument('--update-existing', action='store_true',
                       help='Update existing records instead of skipping them')
    parser.add_argument('--no-verify', action='store_true',
                       help='Disable SSL certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose debug output')

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # SSL verification
    verify_ssl = not args.no_verify
    if not verify_ssl:
        logger.warning("SSL certificate verification is disabled")
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Determine which devices to process
    device_ids = []
    if args.device_id:
        # Specific device IDs provided
        device_ids = args.device_id
        logger.info(f"Processing {len(device_ids)} specified device(s)")
    elif args.device_group_id:
        # Get devices from device group
        logger.info(f"Retrieving devices from device group {args.device_group_id}")
        # Need to authenticate first to get device group
        temp_session = get_firemon_session(args.firemon_url, args.firemon_user, args.firemon_pass, verify_ssl)
        if temp_session:
            device_ids = get_device_group_devices(args.firemon_url, temp_session, args.device_group_id, verify_ssl)
        if not device_ids:
            logger.error("No devices found in device group or failed to retrieve device group")
            sys.exit(1)
    elif args.all_devices:
        # Get all devices in domain
        logger.info("Retrieving all devices in domain")
        temp_session = get_firemon_session(args.firemon_url, args.firemon_user, args.firemon_pass, verify_ssl)
        if temp_session:
            device_ids = get_all_devices(args.firemon_url, temp_session, verify_ssl)
        if not device_ids:
            logger.error("No devices found or failed to retrieve devices")
            sys.exit(1)

    # Get assessment UUIDs (already a list due to action='append')
    assessment_uuids = args.assessment
    logger.info(f"Processing {len(assessment_uuids)} assessment(s)")

    # Process control failures
    logger.info("Starting FireMon to ServiceNow integration...")
    stats = process_control_failures(
        firemon_url=args.firemon_url,
        firemon_user=args.firemon_user,
        firemon_pass=args.firemon_pass,
        snow_url=args.snow_url,
        snow_user=args.snow_user,
        snow_pass=args.snow_pass,
        device_ids=device_ids,
        assessment_uuids=assessment_uuids,
        table_name=args.snow_table,
        verify_ssl=verify_ssl,
        update_existing=args.update_existing,
        min_severity=args.min_severity
    )

    # Print summary
    logger.info("=" * 60)
    logger.info("Integration Summary:")
    logger.info(f"  Devices processed: {stats['devices_processed']}")
    logger.info(f"  Assessments processed: {stats['assessments_processed']}")
    logger.info(f"  Total control failures found: {stats['total_failures']}")
    logger.info(f"    - Rule-level failures: {stats['rule_failures']}")
    logger.info(f"    - Device-level failures: {stats['device_failures']}")
    logger.info(f"  Filtered (below minimum severity): {stats['filtered']}")
    logger.info(f"  Records created: {stats['created']}")
    logger.info(f"  Records updated: {stats['updated']}")
    logger.info(f"  Records skipped: {stats['skipped']}")
    logger.info(f"  Errors: {stats['errors']}")
    logger.info("=" * 60)

    # Exit with appropriate code
    if stats['errors'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
