"""SentinelX discovery: parameter classification.

Every discovered parameter is typed so modules can prioritize the params
most likely to be vulnerable to their class — discovered from the target's
own names/values, never guessed.

Types: url, id, search, file, redirect, auth, misc
"""

from __future__ import annotations

import re


# Param names that suggest the value is a URL the server will fetch.
# Matched case-insensitively as a SUBSTRING of the param name.
# Short generic fragments (api, u, pic) require word boundaries so that
# e.g. "capital" or "rapid" don't match.
URL_PARAM_NAMES = re.compile(
    r"url|uri|link|src|href|path|dest|target|redirect|image|img|file|"
    r"fetch|proxy|feed|\bu\b|page|site|domain|host|avatar|logo|"
    r"picture|\bpic\b|photo|thumb|next|return|continue|goto|redir|"
    r"fetch_url|api_url|callback|webhook|import|load|include|"
    r"resource|document|template|stockapi",
    re.I,
)

# Strong URL-name indicators (very likely SSRF sinks).
URL_PARAM_STRONG = re.compile(
    r"^(url|uri|image|img|fetch|src|href|link|redirect|proxy|feed|"
    r"avatar|logo|picture|webhook|stockapi|api_url|fetch_url)$|"
    r"(fetch|proxy|webhook|ssrf)",
    re.I,
)

ID_PARAM_NAMES = re.compile(
    r"(^|_)(id|uid|user_id|account|no|num|key|serial|invoice|order)(_|$)|"
    r"^[a-z]*id$",
    re.I,
)

SEARCH_PARAM_NAMES = re.compile(
    r"^(q|query|search|keyword|term|s|find|filter|lookup)$",
    re.I,
)

FILE_PARAM_NAMES = re.compile(
    r"file|filename|path|document|download|attachment|template|view|"
    r"page|include|dir|folder",
    re.I,
)

REDIRECT_PARAM_NAMES = re.compile(
    r"redirect|redir|next|return|continue|goto|dest|target|callback|"
    r"returnurl|return_url|redirect_uri",
    re.I,
)

AUTH_PARAM_NAMES = re.compile(
    r"token|auth|session|password|passwd|pwd|secret|apikey|api_key|"
    r"access_token|jwt|"
    # password-change / credential fields (e.g. ?current=, ?new= on change-password)
    # \b for short generic words so "news" / "renew" don't match
    r"current|\bnew\b|\brepeat\b|old_password|confirm|retype|credential|"
    r"passcode|\bpin\b",
    re.I,
)

# A param VALUE that looks like a URL — strongest dynamic signal.
URL_VALUE_RE = re.compile(r"^\s*https?://", re.I)
PROTOCOL_REL_VALUE_RE = re.compile(r"^\s*//[^/]", re.I)


def classify_param(name: str, value: str = "") -> set[str]:
    """Return the set of types for a parameter name/value."""
    types: set[str] = set()
    nl = name.lower()
    if URL_PARAM_STRONG.search(name):
        types.add("url-strong")
    if URL_PARAM_NAMES.search(name):
        types.add("url")
    if value and (URL_VALUE_RE.search(value) or PROTOCOL_REL_VALUE_RE.search(value)):
        # value IS a URL — the server very likely fetches it
        types.add("url")
        types.add("url-value")
    if ID_PARAM_NAMES.search(name):
        types.add("id")
    if SEARCH_PARAM_NAMES.search(name):
        types.add("search")
    if FILE_PARAM_NAMES.search(name):
        types.add("file")
    if REDIRECT_PARAM_NAMES.search(name):
        types.add("redirect")
    if AUTH_PARAM_NAMES.search(name):
        types.add("auth")
    if not types:
        types.add("misc")
    return types


def classify_params(params: dict) -> dict[str, set[str]]:
    """Classify every param in a dict. Returns {name: {types}}."""
    return {k: classify_param(k, str(v)) for k, v in params.items()}


def url_params(params: dict) -> list[str]:
    """Param names worth SSRF-testing, strongest first.

    Includes params whose VALUES look like URLs even if the name doesn't
    (e.g. ?x=http://... discovered from a link).
    """
    scored: list[tuple[int, str]] = []
    for name, value in params.items():
        t = classify_param(name, str(value))
        if "url-value" in t:
            scored.append((0, name))          # value is a URL — top priority
        elif "url-strong" in t:
            scored.append((1, name))
        elif "url" in t:
            scored.append((2, name))
    scored.sort()
    return [n for _, n in scored]


def is_url_param(name: str, value: str = "") -> bool:
    t = classify_param(name, value)
    return bool(t & {"url", "url-strong", "url-value"})
