```mermaid
graph TD
    %% Define Styles
    classDef client fill:#2a2f3a,stroke:#58a6ff,stroke-width:2px,color:#fff
    classDef proxy fill:#161b22,stroke:#3fb950,stroke-width:2px,color:#fff
    classDef layer fill:#0d1117,stroke:#30363d,stroke-width:1px,color:#e6edf3
    classDef backend fill:#1f1f2e,stroke:#f85149,stroke-width:2px,color:#fff
    classDef infra fill:#21262d,stroke:#d29922,stroke-width:2px,color:#fff
    classDef telemetry fill:#1e1e1e,stroke:#8b949e,stroke-width:1px,color:#fff

    subgraph Client [AI Client Environment]
        A["🤖 AI Agent<br/>(e.g., Claude Desktop)"]:::client
    end

    subgraph Bridge [Runtime Shield Gateway (bridge.py)]
        direction TB
        B["📥 MCP Interceptor<br/>(JSON-RPC over stdio)"]:::proxy
        
        L2["🔑 Layer 2: Identity & Auth<br/>(JWT + SPIFFE + JIT Token)"]:::layer
        L5_In["🛡️ Layer 5 (Ingress): NIM Guard<br/>(Jailbreak & Topical Checks)"]:::layer
        L3["📋 Layer 3: Policy Firewall<br/>(mcp-firewall.yaml Rules)"]:::layer
        L4["🕵️ Layer 4: Fraud Engine<br/>(Risk Scoring & Quarantine)"]:::layer
        L1["🏛️ Layer 1: Infrastructure Isolation<br/>(JailFactory: Landlock/NSJail)"]:::layer
        L5_Out["✂️ Layer 5 (Egress): Privacy Router<br/>(PII Regex Scrubbing)"]:::layer

        B -->|"1. Request Tool Execution"| L2
        L2 -->|"2. Authenticated"| L5_In
        L5_In -->|"3. Safe Intent"| L3
        L3 -->|"4. Allowed Action"| L4
        L4 -->|"5. Risk Acceptable"| L1
        
        %% Response Path
        L1 -->|"7. Raw JSON Response"| L5_Out
        L5_Out -->|"8. Scrubbed JSON"| B
    end

    subgraph Identity [External Identity Providers]
        KC["🔐 Keycloak<br/>(User Roles & JWKS)"]:::infra
        SPIRE["🪪 SPIRE Agent<br/>(Workload SVIDs)"]:::infra
    end

    subgraph Execution [Sandboxed Execution Zone]
        Node["📦 Node.js MCP Server<br/>(dist/index.js)"]:::backend
        FS["📁 File System Tools"]:::backend
        KCApi["⚙️ Keycloak Admin Tools"]:::backend
        
        Node --> FS
        Node --> KCApi
    end

    subgraph Telemetry [Audit & Observability]
        Log["📄 bridge.log"]:::telemetry
        Audit["🤖 audit_agent.py<br/>(Background Audit)"]:::telemetry
        DB["💾 telemetry.db"]:::telemetry
        Dash["📊 Live Dashboard<br/>(Port 9090)"]:::telemetry
    end

    %% Connections
    A <-->|"stdio"| B
    
    L2 -.->|"Verify JWT"| KC
    L2 -.->|"Fetch SVID via api.sock"| SPIRE
    
    L1 -->|"6. Forward Request"| Node
    
    B -.->|"Log Event"| Log
    Log -.->|"Tail Logs"| Audit
    Audit -.->|"Write Results"| DB
    B -.->|"Write Event"| DB
    DB -.->|"Poll Metrics"| Dash
```
