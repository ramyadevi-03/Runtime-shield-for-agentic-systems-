# Secure Runtime Shield for Agentic Systems

The **Secure Runtime Shield** is a high-performance, identity-aware security gateway designed to harden AI agents (like Claude Desktop) against prompt injections, data exfiltration, and unauthorized tool use. 

It acts as a stateful interception bridge between the AI and its environment, implementing a **Zero-Trust** architecture for autonomous systems.

---

## 🛡️ 5-Layer Defense Framework

1.  **Identity & Auth (Layer 2):** Dual-factor verification using **Keycloak** (User Roles) and **SPIFFE/SPIRE** (Workload Identity).
2.  **Policy Firewall (Layer 3):** Real-time tool-call inspection against `mcp-firewall.yaml` to block directory traversal and unauthorized path access.
3.  **Fraud Engine (Layer 4):** Behavioral risk scoring that automatically quarantines agents displaying suspicious or repetitive attack patterns.
4.  **Privacy Router (Layer 5):** In-flight PII redaction that scrubs emails and secrets from tool outputs before the AI can see them.
5.  **Infrastructure Isolation (Layer 1):** Secure execution in isolated "Experiment Zones" and Docker-bound containers.

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.10+**
- **Node.js 18+**
- **Docker & Docker Compose**
- **SPIRE** (for Workload Identity)

### 1. Setup Environment
Clone the repository and create a `.env` file based on `.env.example`:
```bash
cp .env.example .env
# Update values for KEYCLOAK_URL, SPIFFE_BRIDGE_ID, and RUNTIME_ROLE
```

### 2. Launch Infrastructure
Start Keycloak and the required database services:
```bash
docker-compose up -d
```

### 3. Build the MCP Server
Install dependencies and compile the TypeScript source:
```bash
npm install
npm run build
```

### 4. Run the Secure Bridge
Launch the Python bridge to begin intercepting tool calls:
```bash
python bridge.py
```

---

## 📊 Security Dashboard
Once the bridge is active, you can monitor all tool calls, risk levels, and redactions in real-time:
- **URL:** `http://127.0.0.1:9090`

## ⚙️ Configuration
- **Firewall Rules:** Modify `mcp-firewall.yaml` to define tool permissions and path guardrails.
- **Roles:** Set `RUNTIME_ROLE=analyst` or `admin` in your `.env` to test different RBAC levels.

---
**Note:** This project is part of a Secure Agentic Runtime research initiative. Use the `--learning` flag with `bridge.py` to discover required policies without enforcing blocks.
