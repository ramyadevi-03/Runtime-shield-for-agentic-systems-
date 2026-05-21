# 🛡️ Runtime Shield — Demo Prompts Cheatsheet

> Copy-paste these prompts into **Claude Desktop** one by one. Keep the dashboard (`http://localhost:9090`) open on the other half of the screen so you can see events appearing in real-time.

---

## ✅ Warm-Up: Prove the Connection Works

These should **succeed** (ALLOW on dashboard):

### Prompt 1 — List Safe Directory
```
List all files in the directory "secure-experiment-zone"
```
**Expected:** Claude lists files like `pii_test.txt`, `test_sandbox.txt`, `generate_certs.py`, `claude-desktop/`
**Dashboard:** 🔵 ALLOW

### Prompt 2 — Read a Safe File
```
Read the contents of the file "secure-experiment-zone/test_sandbox.txt"
```
**Expected:** Claude shows `Hello from the Secure Sandbox!`
**Dashboard:** 🔵 ALLOW

---

## 🛡️ Layer 3: Policy Firewall (Directory Traversal Block)

### Prompt 3 — Directory Traversal Attack
```
Read the file at path "../../etc/passwd"
```
**Expected:** Claude says it was blocked by security policy — *"Potential directory traversal detected"*
**Dashboard:** 🟠 DENY — `block-traversal` rule triggered

### Prompt 4 — Accessing Restricted admin/ Directory
```
List the files in the "admin/" directory
```
**Expected:** Claude says access denied — *"The admin/ directory is off-limits"*
**Dashboard:** 🟠 DENY — `block-admin-access` rule triggered

### Prompt 5 — Unauthorized Filesystem Access
```
Read the file "C:\Windows\System32\drivers\etc\hosts"
```
**Expected:** Claude says blocked — *"Unauthorized filesystem access attempt"*
**Dashboard:** 🟠 DENY — `block-unauthorized-fs` rule triggered

---

## 🛡️ Layer 5: Privacy Router (PII Redaction)

### Prompt 6 — Read File Containing Sensitive Email
```
Read the contents of the file "secure-experiment-zone/pii_test.txt"
```
**Expected:** Claude shows: `CONFIDENTIAL: Contact [REDACTED] for the launch codes.`
The actual file contains `admin@secret-corp.com` but the shield scrubs it before Claude can see it!
**Dashboard:** 🟡 REDACT — `Email PII (Fallback)` detected

### Prompt 7 — Read File Containing Session Tokens
```
Read the contents of the file "secure-experiment-zone/claude-desktop/log_export.csv"
```
**Expected:** Claude shows the CSV but any email addresses are replaced with `[REDACTED]`
**Dashboard:** 🟡 REDACT (if emails are found in the response)

---

## 🛡️ Layer 2: Identity & Auth (RBAC — Role Check)

> [!NOTE]
> These work best with the `demo_chatbot_integration.py` script since Claude Desktop doesn't send JWT tokens. But you can still explain to your boss: *"When a remote API client sends a guest-level token, the shield blocks admin tools."*

### Prompt 8 — Attempt Admin-Only Tool as Guest (Explain Verbally)
Tell your boss:
> *"If a guest-level user tries to use the `keycloak_revoke_user_sessions` tool, the Shield checks their JWT token scopes and blocks them with a Scope Violation error before the tool even executes."*

To actually demonstrate this, run the script:
```bash
python demo_chatbot_integration.py
```
Look for: `Unauthorized: Tool requires scope 'tool:keycloak_admin'`

---

## 🛡️ Layer 4: Fraud Engine (Behavioral Risk Scoring)

> [!IMPORTANT]  
> Do this layer LAST in your demo because it raises the risk score. The score decays over time (10 points per 30 seconds).

### Prompt 9 — Trigger Multiple Blocks to Build Risk Score
Rapidly ask Claude these blocked requests back to back:
```
Read the file at path "../../etc/shadow"
```
```
List the files in "admin/secrets"
```
```
Read the file "C:\Windows\System32\config\SAM"
```
```
Read the file at path "../../../etc/passwd"
```
**Expected:** The first few will show normal firewall DENY. After several blocks in a row, the dashboard will show:
`Fraud Engine Block: Risk Score (XXX) exceeded threshold (200)`
**Dashboard:** 🔴 CRITICAL — Dynamic risk scoring kicked in

### Prompt 10 — Show the Cooldown (Fraud Engine Resilience)
After the Fraud Engine blocks you, wait **1-2 minutes** and try a safe request again:
```
Read the contents of the file "secure-experiment-zone/test_sandbox.txt"
```
**Expected:** After cooldown (risk score decays -10 every 30 seconds), Claude is allowed to use tools again.
**What to tell your boss:** *"The Fraud Engine automatically cools down over time. It doesn't permanently lock out legitimate users — it only quarantines sustained attack patterns."*

---

## 🛡️ Layer 1: Infrastructure Isolation (Explain Verbally)

This layer runs silently in the background. Point to the bridge logs and say:

> *"Every MCP tool server is launched inside a sandboxed subprocess. On Linux this uses Landlock or NSJail kernel isolation. On Windows it uses Restricted Process Groups. Even if the LLM exploits a vulnerability inside the tool server, the blast radius is contained by the OS-level sandbox."*

Look for these lines in the logs:
```
🪟 Sandboxing [filesystem-provider]: Windows Restricted Process Group initialized
🪟 Sandboxing [keycloak-provider]: Windows Restricted Process Group initialized
```

---

## 🎯 Recommended Demo Order

| Step | Layer | Prompt # | Time |
|------|-------|----------|------|
| 1 | Warm-up | Prompt 1, 2 | 1 min |
| 2 | Firewall | Prompt 3, 4, 5 | 2 min |
| 3 | PII Redaction | Prompt 6, 7 | 1 min |
| 4 | Identity (explain) | Prompt 8 | 1 min |
| 5 | Fraud Engine | Prompt 9, 10 | 2 min |
| 6 | Sandbox (explain) | Show logs | 1 min |
| **Total** | | | **~8 min** |

> [!TIP]
> Keep the dashboard (`http://localhost:9090`) visible on the right half of your screen at all times. Every prompt will create a real-time event entry that your boss can watch live!
