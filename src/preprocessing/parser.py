"""
parser.py
---------
PURPOSE: Extract individual parts of a raw HTTP request string.

WHY WE NEED THIS:
A raw HTTP request looks like:
  "GET /search?q=hello HTTP/1.1 Host:demo.com Body:user=test"
We need to break it into parts so we can normalize and inspect
each part separately before feeding it to the ML model or rule engine.
"""

import re
from urllib.parse import urlparse


def parse_request(raw_request: str) -> dict:
    """
    Parse a raw HTTP request string into its components.
    Returns dict with keys: method, path, query, headers, body, raw
    """
    result = {
        "method": "",
        "path": "",
        "query": "",
        "headers": {},
        "body": "",
        "raw": raw_request
    }
    raw = raw_request.strip()

    # Extract HTTP method
    method_match = re.match(
        r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+",
        raw, re.IGNORECASE
    )
    if method_match:
        result["method"] = method_match.group(1).upper()

    # Extract URL path + query
    url_match = re.search(
        r"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP",
        raw, re.IGNORECASE
    )
    if url_match:
        parsed = urlparse(url_match.group(1))
        result["path"]  = parsed.path
        result["query"] = parsed.query

    # Extract Host header
    host_match = re.search(r"Host:\s*(\S+)", raw, re.IGNORECASE)
    if host_match:
        result["headers"]["Host"] = host_match.group(1)

    # Extract User-Agent header
    ua_match = re.search(r"User-Agent:\s*(.+?)(?=\s+\w+:|$)", raw, re.IGNORECASE)
    if ua_match:
        result["headers"]["User-Agent"] = ua_match.group(1).strip()

    # Extract body
    body_match = re.search(r"Body:\s*(.+)", raw, re.IGNORECASE)
    if body_match:
        result["body"] = body_match.group(1).strip()

    return result


def get_all_values(parsed: dict) -> str:
    """Combine all parsed parts into a single string for analysis."""
    parts = [
        parsed.get("method", ""),
        parsed.get("path", ""),
        parsed.get("query", ""),
        " ".join(parsed.get("headers", {}).values()),
        parsed.get("body", "")
    ]
    return " ".join(p for p in parts if p)


if __name__ == "__main__":
    tests = [
        "GET /search?q=<script>alert(1)</script> HTTP/1.1 Host:demo.com",
        "POST /login HTTP/1.1 Host:demo.com Body:user=admin&pass=test",
        "GET /files?name=../../etc/passwd HTTP/1.1 Host:demo.com User-Agent:Mozilla"
    ]
    for t in tests:
        result = parse_request(t)
        print(f"Input:   {t[:60]}")
        print(f"Method:  {result['method']}")
        print(f"Path:    {result['path']}")
        print(f"Query:   {result['query']}")
        print(f"Headers: {result['headers']}")
        print(f"Body:    {result['body']}")
        print()
