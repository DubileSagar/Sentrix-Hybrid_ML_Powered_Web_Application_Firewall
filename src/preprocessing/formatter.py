"""
formatter.py
------------
PURPOSE: Merge parsed + normalized request parts into one structured string.

WHY WE NEED THIS:
The ML model takes a single string as input. Section markers like [QUERY]
help the Transformer understand that <script> in the query string is more
suspicious than in a User-Agent header. Context matters.

Output example:
  [METHOD] get [PATH] /search [QUERY] q=<script>alert(1)</script>
  [HEADERS] host:demo.com [BODY]
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from src.preprocessing.parser import parse_request
from src.preprocessing.normalizer import normalize_request


def format_request(raw_request: str) -> str:
    """
    Full pipeline: parse -> normalize each part -> assemble with markers.
    This is the MAIN function called by the rule engine and ML model.
    """
    parsed  = parse_request(raw_request)
    method  = normalize_request(parsed["method"])
    path    = normalize_request(parsed["path"])
    query   = normalize_request(parsed["query"])
    body    = normalize_request(parsed["body"])
    headers = " ".join(
        f"{k.lower()}:{normalize_request(v)}"
        for k, v in parsed["headers"].items()
    )
    formatted = (
        f"[METHOD] {method} "
        f"[PATH] {path} "
        f"[QUERY] {query} "
        f"[HEADERS] {headers} "
        f"[BODY] {body}"
    )
    return " ".join(formatted.split())


def format_simple(raw_request: str) -> str:
    """
    Simpler version: just normalize the full string.
    Used for the TF-IDF baseline model.
    """
    return normalize_request(raw_request)


if __name__ == "__main__":
    tests = [
        "GET /search?q=<script>alert(1)</script> HTTP/1.1 Host:demo.com",
        "GET /item?id=1' OR '1'='1 HTTP/1.1 Host:demo.com",
        "GET /files?name=../../etc/passwd HTTP/1.1 Host:demo.com",
        "GET /products?category=electronics HTTP/1.1 Host:demo.com",
    ]
    print("Formatter Examples:")
    print("=" * 70)
    for req in tests:
        print(f"INPUT:     {req}")
        print(f"FORMATTED: {format_request(req)}")
        print()
