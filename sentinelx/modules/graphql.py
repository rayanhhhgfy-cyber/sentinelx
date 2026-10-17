"""SentinelX module: GraphQL endpoint detection + introspection testing."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from sentinelx.core.http import ScanClient, ScanConfig
from sentinelx.core.models import Finding, Evidence, raw_request, raw_response


GRAPHQL_PATHS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"]

INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}

REMEDIATION_GQL = (
    "Disable GraphQL introspection in production. Remove GraphiQL/playground "
    "from public deployments. Enforce query depth/complexity limits, "
    "authentication, and field-level authorization."
)


def _ev(method, url, headers, body_sent, resp) -> Evidence:
    rbody = resp.content if resp else b""
    return Evidence(
        request_raw=raw_request(method, url, headers, body_sent),
        response_raw=raw_response(resp.status_code if resp else 0,
                                  dict(resp.headers) if resp else {}, rbody[:2000]),
        proof="",
    )


async def scan_endpoint(client: ScanClient, config: ScanConfig,
                        method: str, url: str, params: dict) -> list[Finding]:
    findings = []
    headers = {"User-Agent": config.user_agent}
    u = urlsplit(url)
    root = f"{u.scheme}://{u.netloc}"

    checked: set[str] = set()
    for path in GRAPHQL_PATHS:
        full = root + path
        if full in checked:
            continue
        checked.add(full)

        # 1. GET probe — playground / GraphiQL UI detection
        resp = await client.get(full, headers=headers)
        if resp:
            body_low = (resp.text or "").lower()
            if any(m in body_low for m in ("graphiql", "graphql playground", "apollo studio")):
                ev = _ev("GET", full, headers, None, resp)
                ev.proof = "GraphQL playground/GraphiQL UI publicly accessible"
                findings.append(Finding(
                    type="Security Misconfiguration", subtype="graphql-playground",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    confidence=0.9, url=full, method="GET", param="",
                    payload="GET " + path, evidence=ev, cwe="CWE-200",
                    owasp="A05:2021 – Security Misconfiguration",
                    remediation=REMEDIATION_GQL,
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                ))
                continue

        # 2. POST introspection query
        post_headers = dict(headers); post_headers["Content-Type"] = "application/json"
        r2 = await client.post(full, json_data=INTROSPECTION_QUERY, headers=post_headers)
        if not r2 or r2.status_code >= 500:
            continue
        try:
            data = r2.json()
        except Exception:
            continue
        schema = data.get("data", {}).get("__schema") if isinstance(data, dict) else None
        if schema and schema.get("queryType", {}).get("name"):
            ev = _ev("POST", full, post_headers, b'{"query":"{__schema{queryType{name}}}"}', r2)
            ev.proof = (f"Introspection enabled — queryType: "
                        f"{schema['queryType']['name']} (schema fully enumerable)")
            findings.append(Finding(
                type="Security Misconfiguration", subtype="graphql-introspection",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                confidence=0.95, url=full, method="POST", param="query",
                payload='{"query":"{__schema{queryType{name}}}"}', evidence=ev,
                cwe="CWE-200", owasp="A05:2021 – Security Misconfiguration",
                remediation=REMEDIATION_GQL,
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            ))
    return findings
