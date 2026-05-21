import os
import requests
import logging
import json
from typing import Dict, Any, List, Tuple

logger = logging.getLogger("redaction_engine")

class RedactionEngine:
    """
    Autonomous AI-Native Redaction Engine using NVIDIA NIM.
    Identifies and redacts PII using semantic entity recognition (No Regex).
    """
    def __init__(self):
        self.api_key = os.getenv("NIM_API_KEY")
        self.base_url = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
        self.model = "meta/llama-3.1-8b-instruct"
        
        if not self.api_key:
            logger.warning("NIM_API_KEY not found. AI Redaction is DISABLED.")

    def _ai_redact(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Use NVIDIA NIM to semantically identify and redact PII.
        """
        if not self.api_key or len(text) < 5:
            return text, []

        system_prompt = """You are a specialized Data Loss Prevention (DLP) agent. 
Your task is to identify and redact Personal Identifiable Information (PII) from the text.
Redact the following entities by replacing them with a label like [REDACTED_NAME], [REDACTED_ADDRESS], [REDACTED_PHONE], [REDACTED_MEDICAL], [REDACTED_KEY], etc.

ENTITIES TO PROTECT:
1. Names of people.
2. Physical Addresses or Locations.
3. Phone numbers and Email addresses.
4. Government IDs (SSN, Passport).
5. Financial data (Credit cards, Bank info).
6. Security tokens (API Keys, JWTs, Passwords).

Respond ONLY with the redacted text. Do not explain anything."""

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text}
            ],
            "temperature": 0.0,
            "max_tokens": 2048
        }

        try:
            response = requests.post(endpoint, headers=headers, json=data, timeout=5)
            if response.status_code == 200:
                redacted_text = response.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                if redacted_text != text:
                    return redacted_text, [{"pattern_name": "ai_semantic_dlp", "match_count": 1}]
                return text, []
            else:
                return text, []
        except Exception as e:
            logger.error(f"NIM Redaction Error: {e}")
            return text, []

    def redact(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Autonomous Redaction Entry Point.
        """
        if self.api_key:
            return self._ai_redact(text)
        return text, []
