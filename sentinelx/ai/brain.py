"""SentinelX AI brain: optional LLM assistance with graceful heuristic fallback.

When OPENAI_API_KEY or ANTHROPIC_API_KEY is present, the brain calls the
provider's chat API directly over httpx (no SDK imports). When no key is
present, every method falls back to deterministic heuristics and never raises.
"""

from __future__ import annotations

import json
import os
import re

import httpx

_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

_ADMINISH = re.compile(r"admin|config|manage|dashboard|panel|debug|console|actuator", re.I)
_APIISH = re.compile(r"/api/|graphql|rest|/v\d+/", re.I)
_AUTHISH = re.compile(r"login|auth|token|session|oauth|jwt", re.I)


def _ep_get(ep, key, default=None):
    if isinstance(ep, dict):
        return ep.get(key, default)
    return getattr(ep, key, default)


class AIBrain:
    """Optional AI layer. Safe to instantiate and call with no API keys."""

    def __init__(self, model: str = "gpt-4o-mini", timeout: float = 30.0):
        self.model = model
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(os.environ.get("OPENAI_API_KEY")
                    or os.environ.get("ANTHROPIC_API_KEY"))

    @property
    def _provider(self) -> str | None:
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        if os.environ.get("ANTHROPIC_API_KEY"):
            return "anthropic"
        return None

    async def _chat(self, system: str, user: str) -> str:
        """Call the configured provider's chat API. Raises on API errors
        (callers catch and fall back to heuristics)."""
        provider = self._provider
        if provider == "openai":
            async with httpx.AsyncClient(trust_env=False,
                                         timeout=self.timeout) as c:
                r = await c.post(
                    _OPENAI_URL,
                    headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
                    json={"model": self.model,
                          "messages": [{"role": "system", "content": system},
                                       {"role": "user", "content": user}],
                          "temperature": 0.2, "max_tokens": 1500},
                )
                r.raise_for_status()
                return r.json()["choices"][0]["message"]["content"]
        elif provider == "anthropic":
            async with httpx.AsyncClient(trust_env=False,
                                         timeout=self.timeout) as c:
                r = await c.post(
                    _ANTHROPIC_URL,
                    headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"],
                             "anthropic-version": "2023-06-01",
                             "content-type": "application/json"},
                    json={"model": "claude-3-5-haiku-latest", "max_tokens": 1500,
                          "system": system,
                          "messages": [{"role": "user", "content": user}]},
                )
                r.raise_for_status()
                return "".join(b.get("text", "")
                               for b in r.json().get("content", []))
        raise RuntimeError("no AI provider configured")

    @staticmethod
    def _extract_json(text: str):
        """Pull the first JSON array/object out of model output."""
        m = re.search(r"(\[.*\]|\{.*\})", text, re.S)
        if not m:
            raise ValueError("no JSON in model output")
        return json.loads(m.group(1))

    def _heuristic_rank(self, endpoints: list) -> list:
        scored = []
        for ep in endpoints:
            url = str(_ep_get(ep, "url", ""))
            params = _ep_get(ep, "params", {}) or {}
            method = str(_ep_get(ep, "method", "GET")).upper()
            score = len(params) * 2
            if _ADMINISH.search(url):
                score += 25
            if _APIISH.search(url):
                score += 6
            if _AUTHISH.search(url):
                score += 5
            if method in ("POST", "PUT", "DELETE", "PATCH"):
                score += 4
            scored.append((score, ep))
        scored.sort(key=lambda t: t[0], reverse=True)
        return [ep for _, ep in scored]

    async def plan_scan(self, endpoints: list) -> list:
        """Rank endpoints by risk, highest first. Heuristic fallback."""
        if not self.enabled:
            return self._heuristic_rank(endpoints)
        try:
            summary = [{"url": str(_ep_get(e, "url", "")),
                        "method": str(_ep_get(e, "method", "GET")),
                        "params": list((_ep_get(e, "params", {}) or {}).keys())}
                       for e in endpoints[:60]]
            text = await self._chat(
                "You are a web security expert prioritizing targets for a "
                "vulnerability scan. Reply with ONLY a JSON array of integers "
                "(indices into the endpoint list), highest risk first.",
                "Rank these endpoints by exploitability risk (auth, admin, "
                f"API, parameter count): {json.dumps(summary)}",
            )
            order = self._extract_json(text)
            ranked = [endpoints[i] for i in order
                      if isinstance(i, int) and 0 <= i < len(endpoints)]
            seen, out = set(), []
            for ep in ranked:
                if id(ep) not in seen:
                    seen.add(id(ep)); out.append(ep)
            # append any endpoints the model dropped
            for ep in endpoints:
                if id(ep) not in seen:
                    out.append(ep)
            return out
        except Exception:
            return self._heuristic_rank(endpoints)

    async def validate_finding(self, finding_dict: dict) -> dict:
        """Second-opinion validation of a finding. Heuristic fallback."""
        if not self.enabled:
            return {"true_positive": True,
                    "confidence": float(finding_dict.get("confidence", 0.5)),
                    "reasoning": "heuristic: evidence present"}
        try:
            slim = {k: finding_dict.get(k) for k in
                    ("type", "subtype", "severity", "url", "method", "param",
                     "payload", "confidence")}
            slim["proof"] = (finding_dict.get("evidence") or {}).get("proof", "")
            text = await self._chat(
                "You are a web security expert triaging scanner findings. Reply "
                "with ONLY a JSON object: "
                '{"true_positive": bool, "confidence": 0.0-1.0, "reasoning": str}.',
                f"Is this a true positive? {json.dumps(slim)}",
            )
            verdict = self._extract_json(text)
            return {"true_positive": bool(verdict.get("true_positive", True)),
                    "confidence": float(verdict.get("confidence", 0.5)),
                    "reasoning": str(verdict.get("reasoning", ""))[:500]}
        except Exception:
            return {"true_positive": True,
                    "confidence": float(finding_dict.get("confidence", 0.5)),
                    "reasoning": "heuristic: evidence present"}

    def chain_findings(self, findings: list) -> list[dict]:
        """Pure-heuristic exploit-chain detection. Works without API keys."""
        def fget(f, key, default=""):
            v = f.get(key, default) if isinstance(f, dict) else getattr(f, key, default)
            return v or default

        by_type: dict[str, list] = {}
        for f in findings:
            t = str(fget(f, "type", "")).lower()
            by_type.setdefault(t, []).append(f)

        def has(needle: str) -> list:
            """Findings whose type/subtype/payload/proof/url mention needle."""
            n = needle.lower()
            out = []
            for t, items in by_type.items():
                for f in items:
                    hay = " ".join([
                        t,
                        str(fget(f, "subtype", "")),
                        str(fget(f, "payload", "")),
                        str((fget(f, "evidence", {}) or {}).get("proof", "")),
                        str(fget(f, "url", "")),
                    ]).lower()
                    if n in hay:
                        out.append(f)
            return out

        def ids(items) -> list:
            return [str(fget(f, "id", "?")) for f in items]

        chains = []
        # LFI + log poisoning -> RCE
        lfi = has("lfi") or has("path traversal") or has("local file")
        if lfi and (has("rce") or has("command injection") or has("log poisoning")):
            chains.append({
                "chain": "LFI + log poisoning → RCE",
                "description": ("Local file inclusion combined with log poisoning "
                                "(e.g. PHP code in User-Agent written to an accessible "
                                "log) yields remote code execution."),
                "finding_ids": ids(lfi),
            })
        # SSRF + cloud metadata -> credential theft
        ssrf = has("ssrf") or has("server-side request")
        if ssrf and (has("169.254") or has("metadata")):
            chains.append({
                "chain": "SSRF + cloud metadata → IAM credential theft",
                "description": ("SSRF reaching the cloud instance metadata service "
                                "(169.254.169.254) can leak IAM credentials and "
                                "escalate to full cloud account takeover."),
                "finding_ids": ids(ssrf),
            })
        # IDOR + JWT -> account takeover
        idor = has("idor") or has("broken access") or has("insecure direct")
        jwt = has("jwt") or has("json web token")
        if idor and jwt:
            chains.append({
                "chain": "IDOR + JWT tampering → account takeover",
                "description": ("Weak JWT validation combined with direct object "
                                "references allows forging tokens or swapping IDs "
                                "to impersonate other users."),
                "finding_ids": ids(idor) + ids(jwt),
            })
        # XSS + CSRF -> session hijack
        xss = has("cross-site scripting") or has("xss")
        csrf = has("csrf") or has("cross-site request")
        if xss and csrf:
            chains.append({
                "chain": "XSS + CSRF → session hijack",
                "description": ("Reflected/stored XSS can be chained with missing "
                                "CSRF protection to perform authenticated actions "
                                "as the victim and steal sessions."),
                "finding_ids": ids(xss) + ids(csrf),
            })
        # Open redirect + OAuth -> token theft
        redir = has("open redirect")
        if redir and (has("oauth") or has("token") or has("callback")):
            chains.append({
                "chain": "Open redirect + OAuth → token theft",
                "description": ("An open redirect on an OAuth callback/authorize "
                                "endpoint can leak authorization codes and access "
                                "tokens to an attacker domain."),
                "finding_ids": ids(redir),
            })
        return chains
