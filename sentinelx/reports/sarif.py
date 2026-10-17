"""SentinelX reports: SARIF 2.1.0 export (GitHub code scanning compatible)."""

from __future__ import annotations

import json
import time
from pathlib import Path

from sentinelx.core.models import Finding


SEV_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

RULE_IDS: dict[str, tuple[str, str, str]] = {
    # rule_id: (name, short description, help URI)
}


def _rule_id(f: Finding) -> str:
    base = f.type.strip().lower()
    base = "".join(c if c.isalnum() else "-" for c in base).strip("-")
    sub = "".join(c if c.isalnum() else "-" for c in f.subtype.strip().lower()).strip("-")
    rid = f"sx/{base}"
    if sub:
        rid += f"/{sub}"
    return rid


def write_sarif(findings: list[Finding], path: str, target: str):
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.type,
                "shortDescription": {"text": f"{f.type} — {f.subtype}" if f.subtype else f.type},
                "fullDescription": {"text": f.remediation or f.type},
                "helpUri": f.references[0] if f.references else "https://owasp.org/",
                "properties": {
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "cvss": f.cvss_score,
                    "cvssVector": f.cvss_vector,
                },
            }
        message = f"{f.type}"
        if f.subtype:
            message += f" [{f.subtype}]"
        if f.evidence.proof:
            message += f" — {f.evidence.proof[:500]}"
        results.append({
            "ruleId": rid,
            "level": SEV_TO_SARIF.get(f.severity, "note"),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "findingId": f.id,
                "severity": f.severity,
                "confidence": f.confidence,
                "method": f.method,
                "param": f.param,
                "payload": f.payload,
                "curl": f.curl_command,
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SentinelX",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/rayanhhhgfy-cyber/sentinelx",
                    "rules": list(rules.values()),
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }],
            "properties": {"target": target},
            "results": results,
        }],
    }
    Path(path).write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
