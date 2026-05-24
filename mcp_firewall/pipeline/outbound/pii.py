"""PII detector — detect personally identifiable information in tool responses."""

from __future__ import annotations

import re

from ..base import OutboundStage
from ...models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallResponse,
)

# PII patterns: (name, regex) — used only when config.pii.outbound_patterns is empty
PII_PATTERNS: list[tuple[str, str]] = [
    ("Email Address", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("Phone (International)", r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{0,4}"),
    ("SSN (US)", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("Credit Card", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    ("IBAN", r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
    ("AHV (Swiss SSN)", r"\b756\.\d{4}\.\d{4}\.\d{2}\b"),
    ("IPv4 Address", r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
]


class PIIDetector(OutboundStage):
    """Detect and optionally redact PII in tool responses."""

    stage = PipelineStage.PII_DETECTOR

    def scan(
        self, response: ToolCallResponse, config: GatewayConfig
    ) -> tuple[ToolCallResponse, PipelineDecision | None]:
        if not config.pii.enabled:
            return response, None

        findings: list[str] = []
        modified = False
        patterns = getattr(config.pii, "outbound_patterns", []) or []

        for i, content_item in enumerate(response.content):
            text = content_item.get("text", "")
            if not text:
                continue

            default_placeholder = config.pii.placeholder
            if not patterns:
                for name, pattern in PII_PATTERNS:
                    matches = list(re.finditer(pattern, text))
                    if matches:
                        findings.append(name)

                        if config.pii.action == Action.REDACT:
                            for match in reversed(matches):
                                text = text[: match.start()] + default_placeholder + text[match.end() :]
                                modified = True
            else:
                for pat_config in patterns:
                    name = pat_config.get("name", "Unknown PII")
                    pattern = pat_config.get("pattern", "")
                    # Per-pattern placeholder → config.pii.placeholder fallback
                    placeholder = pat_config.get("placeholder") or default_placeholder
                    if not pattern:
                        continue
                    try:
                        matches = list(re.finditer(pattern, text))
                        if matches:
                            findings.append(name)

                            if config.pii.action == Action.REDACT:
                                for match in reversed(matches):
                                    text = text[: match.start()] + placeholder + text[match.end() :]
                                    modified = True
                    except Exception:
                        pass

            if modified:
                response.content[i] = {**content_item, "text": text}

        if not findings:
            return response, None

        unique = list(dict.fromkeys(findings))
        decision = PipelineDecision(
            stage=self.stage,
            action=config.pii.action,
            reason=f"PII detected: {', '.join(unique)}",
            severity=config.pii.severity,  # configurable via pii.severity in YAML
            details={"pii_types": unique},
        )
        return response, decision
