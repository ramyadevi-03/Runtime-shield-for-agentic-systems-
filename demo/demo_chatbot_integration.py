import subprocess
import json
import time
import threading
import sys
import os
import jwt

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
BRIDGE_SCRIPT = os.path.join(PROJECT_DIR, "bridge.py")

print("🚀 Starting Secure Runtime Shield Demo Chatbot Integration...")

# Create a test file with PII
os.makedirs(os.path.join(PROJECT_DIR, "secure-experiment-zone"), exist_ok=True)
with open(os.path.join(PROJECT_DIR, "secure-experiment-zone", "pii_test.txt"), "w") as f:
    f.write("CONFIDENTIAL: Contact admin@secret-corp.com for the launch codes.")

# Generate mock JWT tokens
guest_token = jwt.encode({"preferred_username": "guest_user", "scope": "tool:read_file"}, "secret", algorithm="HS256")
admin_token = jwt.encode({"preferred_username": "admin_user", "scope": "tool:read_file tool:write_file tool:keycloak_admin tool:admin_internal"}, "secret", algorithm="HS256")

# Start the bridge
env = os.environ.copy()
# Disable NeMo cloud so we don't depend on external API keys for the demo,
# the regex fallback for PII will still work.
env["NIM_ENABLED"] = "false" 

proc = subprocess.Popen(
    [sys.executable, BRIDGE_SCRIPT],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    encoding='utf-8',
    bufsize=1,
    cwd=PROJECT_DIR,
    env=env
)

def read_stderr():
    for line in proc.stderr:
        # Filter out some noise if necessary, or just print everything
        print(f"[BRIDGE] {line.strip()}")

threading.Thread(target=read_stderr, daemon=True).start()

print("⏳ Waiting for Bridge to initialize...")
time.sleep(3)

def send_request(tool_name, args, token):
    request_id = int(time.time() * 1000)
    req = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": args,
            "metadata": {
                "token": token
            }
        }
    }
    
    print(f"\n🤖 [Chatbot] ➡️ Calling Tool: {tool_name}")
    print(f"🤖 [Chatbot] ➡️ Arguments: {args}")
    
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    
    try:
        resp_line = proc.stdout.readline()
        if resp_line:
            resp = json.loads(resp_line)
            if "error" in resp:
                print(f"🤖 [Chatbot] ❌ Blocked/Error: {json.dumps(resp['error'], indent=2)}")
            else:
                print(f"🤖 [Chatbot] ✅ Response: {json.dumps(resp.get('result', resp), indent=2)}")
        else:
            print("🤖 [Chatbot] ❌ No response (Bridge might have closed)")
    except Exception as e:
        print(f"🤖 [Chatbot] ❌ Failed to parse response: {e} - Raw: {resp_line}")

    time.sleep(1)

print("\n" + "="*60)
print("🛡️ LAYER 2: Identity & Auth (Scope/Role validation)")
print("Attempting to use an admin tool with guest token/role...")
send_request("keycloak_revoke_user_sessions", {"role": "guest", "user_id": "test_user"}, guest_token)

print("\n" + "="*60)
print("🛡️ LAYER 3: Policy Firewall")
print("Attempting Directory Traversal attack with admin token...")
send_request("read_file", {"path": "../../etc/passwd", "role": "admin"}, admin_token)

print("\n" + "="*60)
print("🛡️ LAYER 5: Privacy Router (PII Redaction)")
print("Reading file containing sensitive email (will be intercepted and redacted)...")
send_request("read_file", {"path": "secure-experiment-zone/pii_test.txt", "role": "admin"}, admin_token)

print("\n" + "="*60)
print("🛡️ LAYER 4: Fraud Engine (Honeypot & Quarantine)")
print("Attempting to hit a Honeypot Tool to trigger Quarantine...")
send_request("get_system_config", {"role": "admin", "spiffe_id": "spiffe://runtime-shield/agent"}, admin_token)

print("\n" + "="*60)
print("Testing Quarantine Effect (Should be blocked even for valid benign requests)...")
send_request("read_file", {"path": "secure-experiment-zone/pii_test.txt", "role": "admin", "spiffe_id": "spiffe://runtime-shield/agent"}, admin_token)

print("\n" + "="*60)
print("🛡️ LAYER 1: Infrastructure Isolation")
print("All of the above executed within sandboxed processes (Landlock/NSJail/Windows Job).")
print("Bridge is running successfully as the controller.")
print("="*60)

proc.terminate()
print("\n✅ Demo Complete.")
