"""SentinelX core: payload encoding transforms for evasion testing."""

from __future__ import annotations

import base64
import html
import random
import urllib.parse


def urlencode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def double_urlencode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def triple_urlencode(s: str) -> str:
    return urllib.parse.quote(double_urlencode(s), safe="")


def html_entity(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def html_entity_hex(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in s)


def hex_encode(s: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in s)


def hex_no_percent(s: str) -> str:
    """MySQL-style hex literal: 0x616263 (no % signs)."""
    return "0x" + s.encode("utf-8", "replace").hex()


def octal_escape(s: str) -> str:
    return "".join(f"\\{ord(c):03o}" for c in s)


def unicode_escape(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)


def unicode_fullwidth(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if c == " ":
            out.append("\u3000")
        elif 0x21 <= o <= 0x7E:
            out.append(chr(o + 0xFEE0))
        else:
            out.append(c)
    return "".join(out)


_UTF7_FORCED = {
    "<": "+ADw-", ">": "+AD4-", '"': "+ACI-", "'": "+ACc-",
    "&": "+ACY-", "+": "+-",
}


def utf7_encode(s: str) -> str:
    """UTF-7 (+ADw- style for < > \" ' &)."""
    out = []
    for c in s:
        if c in _UTF7_FORCED:
            out.append(_UTF7_FORCED[c])
        else:
            out.append(c.encode("utf-7").decode("ascii"))
    return "".join(out)


def mixed_case(s: str) -> str:
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in s)


def case_swap_all(s: str) -> str:
    return s.swapcase()


def sql_comment(s: str) -> str:
    return s.replace(" ", "/**/")


def comment_bypass_space(s: str) -> str:
    return s.replace(" ", "/**/")


_SQL_KEYWORDS = [
    "SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "SLEEP", "ORDER", "BY",
    "GROUP", "HAVING", "LIMIT", "INTO", "OUTFILE", "DUMPFILE", "INSERT",
    "UPDATE", "DELETE", "DROP", "TABLE", "FROM", "LIKE", "BENCHMARK",
    "WAITFOR", "DELAY", "CONCAT", "CHAR", "ASCII", "SUBSTRING", "VERSION",
]


def sql_inline_comment(s: str) -> str:
    """MySQL /*!...*/ versioned-comment keyword bypass."""
    out = s
    for kw in _SQL_KEYWORDS:
        out = _ci_replace(out, kw, f"/*!{kw}*/")
    return out


def _ci_replace(text: str, old: str, new: str) -> str:
    import re
    return re.sub(re.escape(old), new, text, flags=re.IGNORECASE)


def double_keyword(s: str) -> str:
    """SELSELECTECT — defeats single-pass keyword strippers."""
    out = s
    for kw in _SQL_KEYWORDS:
        mid = len(kw) // 2
        doubled = kw[:mid] + kw + kw[mid:]
        out = _ci_replace(out, kw, doubled)
    return out


def keyword_space_split(s: str) -> str:
    """Insert /**/ inside long alphabetic words: SEL/**/ECT."""
    import re

    def split_word(m: re.Match) -> str:
        w = m.group(0)
        mid = len(w) // 2
        return w[:mid] + "/**/" + w[mid:]

    return re.sub(r"[A-Za-z]{4,}", split_word, s)


def whitespace_tab(s: str) -> str:
    return s.replace(" ", "%09")


def whitespace_newline(s: str) -> str:
    return s.replace(" ", "%0a")


def whitespace_plus(s: str) -> str:
    return s.replace(" ", "+")


_WS_RANDOM_CHOICES = ["%20", "%09", "%0a", "/**/"]


def whitespace_random(s: str) -> str:
    return "".join(random.choice(_WS_RANDOM_CHOICES) if c == " " else c for c in s)


def tab_space_mix(s: str) -> str:
    out, flip = [], False
    for c in s:
        if c == " ":
            out.append("%09" if flip else "%20")
            flip = not flip
        else:
            out.append(c)
    return "".join(out)


def newline_variants(s: str) -> str:
    choices = ["%0a", "%0d", "%0d%0a"]
    return "".join(random.choice(choices) if c == " " else c for c in s)


def null_byte(s: str) -> str:
    return s + "%00"


def overlong_utf8_2byte(s: str) -> str:
    """Encode each ASCII char as 2-byte overlong UTF-8 (%c0%ae style)."""
    out = []
    for c in s:
        o = ord(c)
        if o < 0x80:
            b1 = 0xC0 | (o >> 6)
            b2 = 0x80 | (o & 0x3F)
            out.append(f"%{b1:02x}%{b2:02x}")
        else:
            out.append(urllib.parse.quote(c, safe=""))
    return "".join(out)


def base64_wrap(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def base64_nopad(s: str) -> str:
    return base64.b64encode(s.encode()).decode().rstrip("=")


def js_charcode(s: str) -> str:
    return "String.fromCharCode(" + ",".join(str(ord(c)) for c in s) + ")"


def utf16_encode(s: str) -> str:
    return "".join(f"%u{ord(c):04x}" for c in s)


TRANSFORMS = {
    "plain": lambda s: s,
    "urlencode": urlencode,
    "double_urlencode": double_urlencode,
    "triple_urlencode": triple_urlencode,
    "html_entity": html_entity,
    "html_entity_hex": html_entity_hex,
    "hex": hex_encode,
    "hex_no_percent": hex_no_percent,
    "octal_escape": octal_escape,
    "unicode_escape": unicode_escape,
    "unicode_fullwidth": unicode_fullwidth,
    "utf7": utf7_encode,
    "mixed_case": mixed_case,
    "case_swap_all": case_swap_all,
    "sql_comment": sql_comment,
    "comment_bypass_space": comment_bypass_space,
    "sql_inline_comment": sql_inline_comment,
    "double_keyword": double_keyword,
    "keyword_space_split": keyword_space_split,
    "tab_ws": whitespace_tab,
    "newline_ws": whitespace_newline,
    "whitespace_plus": whitespace_plus,
    "whitespace_random": whitespace_random,
    "tab_space_mix": tab_space_mix,
    "newline_variants": newline_variants,
    "null_byte": null_byte,
    "overlong_utf8_2byte": overlong_utf8_2byte,
    "base64": base64_wrap,
    "base64_nopad": base64_nopad,
    "js_charcode": js_charcode,
    "utf16": utf16_encode,
}


def apply(s: str, name: str) -> str:
    fn = TRANSFORMS.get(name)
    if not fn:
        raise ValueError(f"unknown transform: {name}")
    return fn(s)
