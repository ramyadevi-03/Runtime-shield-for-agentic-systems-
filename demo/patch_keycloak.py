import requests

KC_URL = "http://localhost:8080"

# 1. Get token
r = requests.post(f"{KC_URL}/realms/master/protocol/openid-connect/token", data={
    "grant_type": "password",
    "client_id": "admin-cli",
    "client_secret": "vsIwGjbvAqpk1tdDeZGEUZAaFPR0ItG3",
    "username": "admin",
    "password": "kavss"
})
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# 2. Get admin-cli client id
cr = requests.get(f"{KC_URL}/admin/realms/master/clients?clientId=admin-cli", headers=headers)
client_id = cr.json()[0]['id']
client_data = cr.json()[0]

# 3. Update client
client_data['standardFlowEnabled'] = True
client_data['redirectUris'] = ["http://localhost:18080/callback"]

ur = requests.put(f"{KC_URL}/admin/realms/master/clients/{client_id}", headers=headers, json=client_data)
if ur.status_code == 204:
    print("Successfully updated admin-cli in Keycloak.")
else:
    print(f"Failed: {ur.status_code} - {ur.text}")
