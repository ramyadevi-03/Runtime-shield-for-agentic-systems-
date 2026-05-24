import requests
import os
from dotenv import load_dotenv

load_dotenv()
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
REALM = os.getenv("KEYCLOAK_REALM", "master")
ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin")
ADMIN_PASS_CANDIDATES = ["admin", "kavss"]

def get_admin_token():
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    for password in ADMIN_PASS_CANDIDATES:
        data = {"grant_type": "password", "client_id": "admin-cli", "username": ADMIN_USER, "password": password}
        try:
            r = requests.post(url, data=data, timeout=5)
            if r.status_code == 200: return r.json()["access_token"]
            secret = os.getenv("KEYCLOAK_CLIENT_SECRET")
            if secret:
                data["client_secret"] = secret
                r = requests.post(url, data=data, timeout=5)
                if r.status_code == 200: return r.json()["access_token"]
        except: pass
    return None

def update_user(token, username, password):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?username={username}"
    r = requests.get(url, headers=headers, timeout=5)
    users = r.json()
    
    if users:
        user_id = users[0]["id"]
    else:
        create_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"
        user_data = {"username": username, "enabled": True, "emailVerified": True, "credentials": [{"type": "password", "value": password, "temporary": False}]}
        r = requests.post(create_url, json=user_data, headers=headers, timeout=5)
        if r.status_code == 201:
            print(f"Created user {username}")
            return
        else: return

    pass_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/reset-password"
    pass_data = {"type": "password", "value": password, "temporary": False}
    r = requests.put(pass_url, json=pass_data, headers=headers, timeout=5)
    if r.status_code == 204:
        print(f"Set password for {username} to '{password}'")

def main():
    token = get_admin_token()
    if not token: return
    update_user(token, "admin", "admin")
    update_user(token, "user", "user")

if __name__ == "__main__":
    main()
