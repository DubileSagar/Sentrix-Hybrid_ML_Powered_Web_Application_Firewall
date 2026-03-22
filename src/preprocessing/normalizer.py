"""
normalizer.py
-------------
PURPOSE: Clean and standardize request text WITHOUT destroying attack signals.

WHY WE NEED THIS:
Attackers obfuscate attacks using URL encoding (%3Cscript%3E),
mixed case (UnIoN SeLeCt), extra spaces, SQL comments (UNION/**/SELECT).
If we don't normalize, the same attack in different encodings looks
completely different to our ML model.

CRITICAL: Do NOT remove < > ' " ; = ../ -- () % /
These ARE the attack signals. Normal NLP strips them — we KEEP them.
"""

import re
from urllib.parse import unquote


def url_decode(text: str) -> str:
    """
    URL-decode twice to catch double encoding.
    %3Cscript%3E -> <script>
    %2527        -> %27 -> '
    """
    return unquote(unquote(text))


def normalize_case(text: str) -> str:
    """Lowercase everything so UNION and union look the same."""
    return text.lower()


def normalize_spaces(text: str) -> str:
    """
    Remove SQL comment blocks UNION/**/SELECT -> UNION SELECT
    Collapse multiple spaces/tabs/newlines into one space.
    """
    text = re.sub(r'/\*.*?\*/', ' ', text)   # remove /**/ comments
    text = re.sub(r'\s+', ' ', text)          # collapse whitespace
    return text.strip()


def normalize_request(raw_text: str) -> str:
    """
    Full normalization pipeline: url_decode -> lowercase -> normalize_spaces
    NEVER strips < > ' " ; = ../ -- () % /  — these are attack signals.
    """
    text = url_decode(raw_text)
    text = normalize_case(text)
    text = normalize_spaces(text)
    return text


if __name__ == "__main__":
    tests = [
        "GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1",
        "GET /item?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1",
        "GET /item?id=1 UNION/**/SELECT/**/password/**/FROM/**/users",
        "GET /files?name=..%2F..%2Fetc%2Fpasswd HTTP/1.1",
    ]
    print("Normalization Examples:")
    print("-" * 60)
    for t in tests:
        print(f"BEFORE: {t}")
        print(f"AFTER:  {normalize_request(t)}")
        print()
