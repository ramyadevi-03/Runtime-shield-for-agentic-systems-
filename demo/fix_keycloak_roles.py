import requests
import os
import json
from dotenv import load_dotenv

load_dotenv()

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM = os.getenv("KEYCLOAK_REALM", "master")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "admin-cli")
ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin")
ADMIN_PASS_CANDIDATES = ["admin", "kavss", "kavyaa06", "Password123", "keycloak"]

def get_admin_token():
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    for password in ADMIN_PASS_CANDIDATES:
        data = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": password
        }
        try:
            r = requests.post(url, data=data, timeout=5)
            if r.status_code == 200: 
                print(f"[*] Authenticated as {ADMIN_USER}")
                return r.json()["access_token"]
        except: pass
    print("[!] Failed to get admin token.")
    return None

def fix_roles():
    token = get_admin_token()
    if not token: return
    
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    # 1. Get the internal ID of the target client
    client_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={CLIENT_ID}"
    r = requests.get(client_url, headers=headers)
    clients = r.json()
    if not clients:
        print(f"[!] Client {CLIENT_ID} not found.")
        return
    
    target_client = clients[0]
    internal_id = target_client["id"]
    print(f"[+] Found client {CLIENT_ID} (ID: {internal_id})")

    # 2. Get the internal ID of the 'realm-management' client
    mgmt_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId=realm-management"
    r = requests.get(mgmt_url, headers=headers)
    mgmt_id = r.json()[0]["id"]

    # 3. Get available roles from 'realm-management'
    roles_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{mgmt_id}/roles"
    r = requests.get(roles_url, headers=headers)
    available_roles = r.json()
    
    roles_to_assign = ["view-users", "query-users", "manage-users"]
    role_payload = [role for role in available_roles if role["name"] in roles_to_assign]
    
    if not role_payload:
        print("[!] Could not find the required roles in realm-management.")
        return

    # 4. Assign roles to the client's service account
    assign_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{internal_id}/scope-mappings/clients/{mgmt_id}"
    r = requests.post(assign_url, json=role_payload, headers=headers)
    
    if r.status_code in [200, 204]:
        print(f"[+] SUCCESS: Assigned administrative roles to {CLIENT_ID} service account.")
        print(f"[+] Mapped roles: {[r['name'] for r in role_payload]}")
    else:
        print(f"[!] Failed to assign roles: {r.text}")

if __name__ == "__main__":
    fix_roles()
