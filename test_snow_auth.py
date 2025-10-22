#!/usr/bin/env python3
"""
Test ServiceNow authentication and table access
"""
import requests
import json
import argparse
import getpass
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_servicenow_auth(snow_url, snow_user, snow_pass, table_name="em_event"):
    """Test ServiceNow authentication and table access"""

    print(f"\n{'='*70}")
    print(f"ServiceNow Authentication & Access Test")
    print(f"{'='*70}")
    print(f"Instance: {snow_url}")
    print(f"Username: {snow_user}")
    print(f"Table: {table_name}")
    print(f"{'='*70}\n")

    # Create session with basic auth
    session = requests.Session()
    session.auth = (snow_user, snow_pass)
    session.headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Test 1: Read from table
    print("Test 1: GET request (read access)")
    print(f"  URL: {snow_url}/api/now/table/{table_name}")

    try:
        response = session.get(
            f"{snow_url}/api/now/table/{table_name}",
            params={'sysparm_limit': 1},
            verify=False
        )

        print(f"  Status Code: {response.status_code}")

        if response.status_code == 200:
            print(f"  ✓ Authentication successful!")
            print(f"  ✓ Table '{table_name}' is accessible")
            data = response.json()
            result = data.get('result', [])
            print(f"  ✓ Retrieved {len(result)} record(s)")
        elif response.status_code == 401:
            print(f"  ✗ Authentication failed (401)")
            print(f"  ✗ Check username and password")
            print(f"  Response: {response.text}")
            return False
        elif response.status_code == 403:
            print(f"  ✗ Forbidden (403)")
            print(f"  ✗ User lacks read permission on '{table_name}' table")
            print(f"  Response: {response.text}")
            return False
        elif response.status_code == 404:
            print(f"  ✗ Table not found (404)")
            print(f"  ✗ Table '{table_name}' does not exist")
            print(f"  Response: {response.text}")
            return False
        else:
            print(f"  ✗ Unexpected status code: {response.status_code}")
            print(f"  Response: {response.text}")
            return False

    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

    print()

    # Test 2: Try to create a minimal record
    print("Test 2: POST request (write access)")

    if table_name == "em_event":
        # Minimal em_event payload
        test_payload = {
            "source": "Test Script",
            "node": "Test Node",
            "type": "Test Event",
            "severity": "5",
            "description": "Test event - please delete",
            "message_key": f"TEST-{snow_user}-12345"
        }
    else:
        # Minimal incident payload
        test_payload = {
            "short_description": f"Test from {snow_user} - please delete",
            "description": "This is a test. Please delete."
        }

    print(f"  Payload: {json.dumps(test_payload, indent=2)}")

    try:
        response = session.post(
            f"{snow_url}/api/now/table/{table_name}",
            data=json.dumps(test_payload),
            verify=False
        )

        print(f"  Status Code: {response.status_code}")

        if response.status_code == 201:
            print(f"  ✓ Record created successfully!")
            result = response.json().get('result', {})
            sys_id = result.get('sys_id')
            print(f"  ✓ Record sys_id: {sys_id}")

            # Clean up - delete the test record
            if sys_id:
                print(f"\n  Cleaning up test record...")
                del_response = session.delete(
                    f"{snow_url}/api/now/table/{table_name}/{sys_id}",
                    verify=False
                )
                if del_response.status_code == 204:
                    print(f"  ✓ Test record deleted")
                else:
                    print(f"  ⚠ Could not delete test record (sys_id: {sys_id})")
            return True

        elif response.status_code == 401:
            print(f"  ✗ Authentication failed (401)")
            print(f"  Response: {response.text}")
            return False
        elif response.status_code == 403:
            print(f"  ✗ Forbidden (403)")
            print(f"  ✗ User lacks write permission on '{table_name}' table")
            print(f"  Response: {response.text}")
            return False
        elif response.status_code == 400:
            print(f"  ✗ Bad Request (400)")
            print(f"  ✗ Missing required fields or invalid data")
            print(f"  Response: {response.text}")
            return False
        else:
            print(f"  ✗ Unexpected status code: {response.status_code}")
            print(f"  Response: {response.text}")
            return False

    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

    print(f"\n{'='*70}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test ServiceNow authentication and table access')
    parser.add_argument('--snow-url', help='ServiceNow instance URL')
    parser.add_argument('--snow-user', help='ServiceNow username')
    parser.add_argument('--snow-pass', help='ServiceNow password')
    parser.add_argument('--snow-table', default='em_event', help='Table name to test (default: em_event)')

    args = parser.parse_args()

    # Prompt for credentials if not provided
    snow_url = args.snow_url
    if not snow_url:
        snow_url = input("ServiceNow instance URL: ").strip()

    snow_user = args.snow_user
    if not snow_user:
        snow_user = input("ServiceNow username: ").strip()

    snow_pass = args.snow_pass
    if not snow_pass:
        snow_pass = getpass.getpass("ServiceNow password: ")

    success = test_servicenow_auth(snow_url, snow_user, snow_pass, args.snow_table)

    if success:
        print("\n✓ All tests passed! ServiceNow authentication and access is working.\n")
        exit(0)
    else:
        print("\n✗ Tests failed. Please check the errors above.\n")
        exit(1)
