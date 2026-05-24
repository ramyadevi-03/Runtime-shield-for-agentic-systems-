# 🔒 Dynamic PII Redaction & Data Loss Prevention — Teammate Implementation Guide

> [!IMPORTANT]
> This document details the **Dynamic PII Redaction & Data Loss Prevention (Layer 5)** architecture within the Secure Runtime Shield. It covers the dual-layer defense (Microsoft Presidio NLP + NVIDIA NIM Semantic DLP), special formatting interceptors, and configuration engines.

---

## 1. Architectural Overview: Double-Defense PII Shielding

To prevent sensitive enterprise data and Personal Identifiable Information (PII) from being leaked (either exfiltrated by a hijacked agent or exposed to LLM providers during reasoning), the system implements a **Double-Defense Outbound Sanitization Pipeline**:

```
           +---------------------------------------------+
           |           Raw Tool/LLM Output               |
           +---------------------------------------------+
                                  |
                                  v
           +---------------------------------------------+
           |     1. JSON Interceptor & Table Parser      |
           |   (Transforms CSV/JSON arrays to Markdown)  |
           +---------------------------------------------+
                                  |
                                  v
           +---------------------------------------------+
           |       2. Markdown Header Skipper            |
           |    (Isolates headers to protect names)      |
           +---------------------------------------------+
                                  |
                                  v
                     Is NVIDIA_API_KEY active?
                     /                       \
                  Yes                         No
                  /                             \
                 v                               v
+-------------------------------+ +-------------------------------+
|     Option B: AI-Native       | |      Option A: Local NLP      |
|  Semantic NIM Redaction       | |    Microsoft Presidio engine  |
| (Uses Llama 3.1 8B semantic)  | |  (Uses Named Entity Recogn.)  |
+-------------------------------+ +-------------------------------+
                 \                               /
                  \                             /
                   v                           v
           +---------------------------------------------+
           |         3. Dynamic Regex Fallback           |
           |      (Applies CC and phone patterns)        |
           +---------------------------------------------+
                                  |
                                  v
           +---------------------------------------------+
           |        Clean, Sanitized Output Stream       |
           +---------------------------------------------+
```

---

## 2. Detailed File Breakdown

Here is where the PII Redaction implementation resides in the codebase:

```
Runtime-shield-for-agentic-systems/
├── .env                              ← ⚙️ Core configurations (NVIDIA_API_KEY, NIM_BASE_URL)
├── mcp-firewall.yaml                 ← 📋 Policy File: Inbound/outbound rules and PII parameters
│
├── bridge.py                         ← 🧠 Gateway: Core interceptor, table parsing, header-skipping,
│                                        and Presidio integration routines
│
├── mcp_firewall/privacy/
│   └── redaction_engine.py           ← 🤖 AI Redaction: Out-of-box semantic DLP classifier (NIM Llama 3.1)
│
└── damn-vulnerable-llm-agent/
    └── tools.py                      ← 🔌 Tool Level: Local _redact_pii_for_user() logic ensuring PII
                                         is anonymized at the source before UI rendering
```

---

## 3. Core Redaction Engines

### 3.1 Option A: Local Microsoft Presidio NLP Engine
When running locally or offline, the system defaults to **Microsoft Presidio NLP**.
- **Named Entity Recognition (NER):** Utilizes SpaCy language models to identify names, locations, emails, credit cards, and SSNs.
- **Dynamic Policy Configurations:** Reads `pii` configs directly from `mcp-firewall.yaml`:
  - `presidio_entities: [ALL]`: Scans for all SpaCy-supported recognizers dynamically.
  - `presidio_exclude_entities: [DATE_TIME]`: Prevents false-positives (like row IDs or transaction timestamps flagged as birthdates/years).
- **Placeholder Customization:** Replaces detected entities with custom placeholders (`presidio_operators` in YAML) such as `[REDACTED-EMAIL]`, `[REDACTED-CC]`, etc.
- **Regex Fallbacks:** If NLP models miss custom patterns, the pipeline applies regular expression overlays for Credit Cards (`\b\d{4}-\d{4}-\d{4}-\d{4}\b`) and Phone numbers.

### 3.2 Option B: AI-Native Semantic DLP (`redaction_engine.py`)
If `NVIDIA_NIM_API_KEY` (or `NVIDIA_API_KEY`) is active in `.env`, the system automatically routes data through [redaction_engine.py](file:///c:/Users/Lenovo/Desktop/Runtime-shield-%20login/Runtime-shield-for-agentic-systems/mcp_firewall/privacy/redaction_engine.py):
- **Model Resolution:** Resolves model parameters in priority order: YAML Config (`nim_model`) $\rightarrow$ Env Variable (`NIM_MODEL`) $\rightarrow$ Enterprise default (`meta/llama-3.1-8b-instruct`).
- **Enterprise DLP Prompts:** Connects to the NIM completions endpoint using a highly strict DLP prompt that demands zero summaries, warnings, notes, or rephrasing, and enforces:
  - **The Tabular Rule:** Keep headers completely intact; redact only actual personal instances in data rows.
  - **The Verbatim Rule:** If no PII is found, return the text exactly character-for-character.
  - **The Paths Rule:** Do not redact folder names, directories, or standard files (like `/secure-experiment-zone`).
  - **The Input Container Rule:** Encloses text in boundary markers (`--- START INPUT TEXT ---`) to prevent prompt injections inside tool outputs from executing or hijacking the DLP engine.

---

## 4. Context-Aware Safety Interceptors

Running raw NLP or LLM models directly on developer logs or CSV buffers has significant side effects, such as corrupting JSON wrappers or stripping table headers. The gateway implements three custom engineering solutions to solve this:

### 4.1 The JSON Interceptor Rule
When the chatbot proxy detects JSON-RPC blocks (especially final ReAct blocks like `Final Answer` containing an `action_input` string), it isolates the payload before scanning:
1. Locates the outermost `{` and `}` boundaries.
2. Extracts and parses the JSON.
3. Performs formatting and PII redaction **strictly inside** the `"action_input"` string value.
4. Serializes the updated object back into the JSON wrapper.
This prevents the NLP engine from corrupting JSON keys (`"action"`, `"action_input"`) which would otherwise trigger parsing errors in LangChain.

### 4.2 The Tabular Converter & Formatter
LLMs and database drivers frequently output unformatted CSV, TSV, or raw JSON arrays. To ensure readability, [bridge.py](file:///c:/Users/Lenovo/Desktop/Runtime-shield-%20login/Runtime-shield-for-agentic-systems/bridge.py) automatically processes these:
- **`format_embedded_json_arrays()`:** Finds raw JSON arrays of objects and converts them to Markdown pipe tables.
- **`format_embedded_tabular_segments()`:** Scans line-by-line for comma-separated or tab-separated lines and converts them into structured Markdown tables.
This runs **before** redaction so that table schemas are created and column headers are properly aligned.

### 4.3 The Markdown Table Header Skipper
Because column headers like "Name", "Email", or "Location" are standard English nouns, NLP models often redact them, destroying the table format. To prevent this, the gateway uses:
```python
def redact_pii_with_presidio(text: str, is_raw: bool = False, skip_headers: bool = True) -> str:
    if skip_headers and isinstance(text, str) and text.strip():
        if is_markdown_table(text):
            lines = text.split('\n')
            if len(lines) >= 3:
                header = lines[0]      # | Name | Email | Amount |
                separator = lines[1]   | ---  | ---   | ---    |
                rows = '\n'.join(lines[2:]) # Data rows containing actual values
                
                # Apply PII redaction ONLY to the data rows
                redacted_rows = redact_pii_with_presidio(rows, is_raw=True, skip_headers=False)
                return header + '\n' + separator + '\n' + redacted_rows
```
This protects structural headers while ensuring that every data entry underneath is fully sanitized.

---

## 5. End-to-End PII Redaction Request Flow

Here is the step-by-step trace when Marty McFly queries transaction records containing PII:

```text
  💻 Client app (Streamlit)           🛡️ Security Gateway                  💾 transaction.db
         |                                     |                                   |
         | --- [GetUserTransactions(1)] ------>|                                   |
         |                                     |                                   |
         |                                     | --- Fetch transactions ---------->|
         |                                     |                                   |
         |                                     |<--- Return raw CSV text ----------|
         |                                           Row 1: userId,reference,recipient,amount
         |                                           Row 2: 1,Skateboard,marty.mcfly@gmail.com,150
         |                                     |                                   |
         |                                     | --- Transform to MD Table ------ |
         |                                     |     | userId | reference  | ... |
         |                                     |     | 1      | Skateboard | ... |
         |                                     |                                   |
         |                                     | --- Header-Skipping Redactor --- |
         |                                     |     Headers: preserved verbatim   |
         |                                     |     Email: replaced by [REDACTED] |
         |                                     |                                   |
         |<--- Return Sanitized MD Table ------|                                   |
```

---

## 6. Configuration Reference (`mcp-firewall.yaml`)

Share this YAML block with your teammate to make sure PII shielding is active:

```yaml
# Inbound/Outbound PII Guardrail
pii:
  enabled: true
  action: redact
  severity: medium
  placeholder: "[PII REDACTED]"
  
  # Entity types for Microsoft Presidio NER (ALL turns on all SpaCy recognizers)
  presidio_entities:
    - ALL
    
  # Entity types to skip to prevent false-positives
  presidio_exclude_entities:
    - DATE_TIME
    
  # Custom per-entity replacement tokens
  presidio_operators:
    EMAIL_ADDRESS: "[REDACTED-EMAIL]"
    CREDIT_CARD: "[REDACTED-CC]"
    PHONE_NUMBER: "[REDACTED-PHONE]"
    US_SSN: "[REDACTED-SSN]"
    
  # Dynamic fallback filters
  regex_fallbacks:
    - name: "Credit Card"
      pattern: '\b\d{4}-\d{4}-\d{4}-\d{4}\b'
      placeholder: '[REDACTED-CC]'
    - name: "Phone"
      pattern: '\b\d{3}-\d{4}\b'
      placeholder: '[REDACTED-PHONE]'
```

---

## 7. How to Test and Verify PII Redaction

To verify that dynamic PII redaction is working correctly:

1. **Verify Presidio Startup Warmup:**
   Start the gateway proxy:
   ```bash
   python bridge.py
   ```
   *Expected console logs:*
   `⏳ Warming up Microsoft Presidio NLP engine...`
   `✅ Microsoft Presidio NLP engine fully warmed up!`

2. **Trigger PII Data Query:**
   Select the Standard User persona (Marty McFly) and ask the Chatbot:
   `"Show my recent transactions"`
   
3. **Verify Outbound Redaction:**
   - **Expected UI Result:** The Streamlit assistant responds with a beautifully structured Markdown table. The receipt email column shows `[REDACTED-EMAIL]` instead of Marty's real email, and George McFly's transaction shows `[REDACTED-SSN]` instead of his SSN.
   - **Verify Log File Audit:** Check `bridge.log`:
     `✂️ PII redacted via Microsoft Presidio NLP — types: ['EMAIL_ADDRESS', 'US_SSN']`
