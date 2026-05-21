"""Quick Keycloak diagnostics script."""
import requests
import json

KC_URL = "http://localhost:8080"

try:
    print("Getting token with secret...")
    r = requests.post(f"{KC_URL}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password",
        "client_id": "admin-cli",
        "client_secret": "vsIwGjbvAqpk1tdDeZGEUZAaFPR0ItG3",
        "username": "admin",
        "password": "kavss"
    }, timeout=10)
    print(f"Status: {r.status_code}")
    
    if r.status_code == 200:
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # List clients in master
        print("\n=== Clients in master ===")
        cr = requests.get(f"{KC_URL}/admin/realms/master/clients", headers=headers, timeout=10)
        for c in cr.json():
            if c['clientId'] in ['admin-cli', 'security-admin-console']:
                print(f"  Client: {c['clientId']}")
                print(f"    public: {c.get('publicClient')}")
                print(f"    directAccess: {c.get('directAccessGrantsEnabled')}")
                print(f"    standardFlow: {c.get('standardFlowEnabled')}")
                print(f"    redirectUris: {c.get('redirectUris', [])}")
                print(f"    secret exists: {bool(c.get('secret'))}")
                print()
except Exception as e:
    print(f"Error: {e}")
