# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

"""
Test script for validating the dynamic TTL feature in Kerberos auth.
Tests both with and without custom TTL values.
"""

import json
import kerberos
import requests
import sys

def get_kerberos_token(host):
    """Get a Kerberos SPNEGO token for the given host."""
    service = "HTTP@{}".format(host)
    rc, vc = kerberos.authGSSClientInit(service=service, mech_oid=kerberos.GSS_MECH_OID_SPNEGO)
    kerberos.authGSSClientStep(vc, "")
    return kerberos.authGSSClientResponse(vc)

def login_with_ttl(host, namespace, ttl=None):
    """
    Login to Vault with Kerberos auth, optionally specifying a TTL.
    Returns the response JSON.
    """
    kerberos_token = get_kerberos_token(host)

    url = "http://{}/v1/{}auth/kerberos/login".format(host, namespace)
    headers = {'Authorization': 'Negotiate ' + kerberos_token}

    if ttl:
        # Send TTL in the JSON body
        response = requests.post(url, headers=headers, json={'ttl': ttl})
    else:
        response = requests.post(url, headers=headers)

    if response.status_code != 200:
        print("Login failed with status {}: {}".format(response.status_code, response.text))
        return None

    return response.json()

def test_default_ttl(host, namespace):
    """Test login without custom TTL."""
    print("Testing login without custom TTL...")
    result = login_with_ttl(host, namespace)
    if not result:
        return False

    auth = result.get('auth', {})
    token = auth.get('client_token')
    lease_duration = auth.get('lease_duration', 0)

    if not token:
        print("FAIL: No client token received")
        return False

    print("SUCCESS: Got token with default lease_duration={}s".format(lease_duration))
    return True

def test_custom_ttl(host, namespace, ttl_str, expected_seconds):
    """Test login with custom TTL."""
    print("Testing login with TTL='{}'...".format(ttl_str))
    result = login_with_ttl(host, namespace, ttl=ttl_str)
    if not result:
        return False

    auth = result.get('auth', {})
    token = auth.get('client_token')
    lease_duration = auth.get('lease_duration', 0)

    if not token:
        print("FAIL: No client token received")
        return False

    if lease_duration != expected_seconds:
        print("FAIL: Expected lease_duration={}s, got {}s".format(expected_seconds, lease_duration))
        return False

    print("SUCCESS: Got token with lease_duration={}s (expected {}s)".format(lease_duration, expected_seconds))
    return True

def test_invalid_ttl(host, namespace):
    """Test that invalid TTL returns an error."""
    print("Testing login with invalid TTL='invalid'...")
    kerberos_token = get_kerberos_token(host)

    url = "http://{}/v1/{}auth/kerberos/login".format(host, namespace)
    headers = {'Authorization': 'Negotiate ' + kerberos_token}
    response = requests.post(url, headers=headers, json={'ttl': 'invalid'})

    if response.status_code == 400:
        error_msg = response.json().get('errors', [''])[0]
        if 'invalid ttl format' in error_msg.lower():
            print("SUCCESS: Invalid TTL correctly rejected with error: {}".format(error_msg))
            return True

    print("FAIL: Expected 400 error for invalid TTL, got status {}".format(response.status_code))
    return False

def main():
    if len(sys.argv) < 3:
        print("Usage: {} <vault_host> <namespace>".format(sys.argv[0]))
        sys.exit(1)

    prefix = sys.argv[1]
    namespace = sys.argv[2]
    host = prefix + ".matrix.lan:8200"

    print("=" * 60)
    print("TTL Feature Tests")
    print("Host: {}".format(host))
    print("Namespace: {}".format(namespace))
    print("=" * 60)

    results = []

    # Test 1: Default TTL
    results.append(("Default TTL", test_default_ttl(host, namespace)))

    # Test 2: Custom TTL of 5 minutes (300 seconds)
    results.append(("Custom TTL 5m", test_custom_ttl(host, namespace, "5m", 300)))

    # Test 3: Custom TTL of 1 hour (3600 seconds)
    results.append(("Custom TTL 1h", test_custom_ttl(host, namespace, "1h", 3600)))

    # Test 4: Custom TTL of 30 seconds
    results.append(("Custom TTL 30s", test_custom_ttl(host, namespace, "30s", 30)))

    # Test 5: Invalid TTL
    results.append(("Invalid TTL", test_invalid_ttl(host, namespace)))

    print("=" * 60)
    print("Results Summary:")
    all_passed = True
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print("  {}: {}".format(name, status))
        if not passed:
            all_passed = False
    print("=" * 60)

    if all_passed:
        print("All TTL tests passed!")
        sys.exit(0)
    else:
        print("Some TTL tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
