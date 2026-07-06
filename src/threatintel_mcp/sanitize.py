"""Output sanitization helpers.

Security design note
--------------------
Everything returned by these tools is CONTENT FROM THIRD-PARTY APIS, which in
turn is content from *attacker-controlled infrastructure* (a malicious URL, a
domain's WHOIS record, a sandbox's captured page title, ...). When that text is
handed back to an LLM as tool output it becomes a prompt-injection surface, and
when a human analyst reads it in a terminal a live URL is a click-hazard.

We therefore treat all upstream response content as UNTRUSTED and defang
indicators before they leave this process:

    http://evil.test/x   ->  hxxp://evil[.]test/x
    1.2.3.4              ->  1[.]2[.]3[.]4

Defanging is intentionally lossy-looking but reversible by a human; it prevents
accidental navigation and reduces the chance an indicator is interpreted as a
live instruction/link downstream.
"""

from __future__ import annotations

import re

# Matches scheme://... URLs. Kept deliberately simple; we only need to catch the
# common shapes that show up in threat-intel payloads (http, https, ftp).
_URL_RE = re.compile(r"\b(https?|ftp)://", flags=re.IGNORECASE)

# A dotted-quad IPv4. We defang the dots but leave the octets intact.
_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def defang(value: str) -> str:
    """Defang a single string: neutralize URL schemes and dotted indicators.

    Idempotent-ish for typical inputs; safe to call on arbitrary text.
    """
    if not value:
        return value

    # Neutralize schemes first (http -> hxxp, https -> hxxps, ftp -> fxp).
    def _scheme(match: re.Match[str]) -> str:
        scheme = match.group(1).lower()
        replacement = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}[scheme]
        return f"{replacement}://"

    out = _URL_RE.sub(_scheme, value)

    # Neutralize IPv4 dots.
    out = _IPV4_RE.sub(lambda m: "[.]".join(m.groups()), out)

    # Neutralize the remaining "domain dots". We only touch a dot when it sits
    # between two alphanumerics to avoid mangling ellipses/prose, and we skip
    # dots already inside a "[.]" produced above.
    out = re.sub(r"(?<=[A-Za-z0-9])\.(?=[A-Za-z0-9])", "[.]", out)

    return out


def defang_deep(obj: object) -> object:
    """Recursively defang every string in a nested dict/list structure.

    Used on the compact summaries we build so that no live indicator escapes,
    regardless of which field it landed in.
    """
    if isinstance(obj, str):
        return defang(obj)
    if isinstance(obj, dict):
        return {k: defang_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [defang_deep(v) for v in obj]
    return obj
