"""
rule_engine.py
--------------
PURPOSE: Catch OBVIOUS attacks instantly using regex patterns.

WHY WE NEED THIS:
1. SPEED: Regex is 1000x faster than running DistilBERT.
2. RELIABILITY: Textbook attacks should ALWAYS be caught even if ML fails.
3. EXPLAINABILITY: When blocked by a rule, we know exactly which pattern matched.

Run AFTER normalization so encoded attacks are also caught.
"""

import re
from typing import Tuple, Optional

RULES = {
    "sqli": [
        r"'\s*or\s+\d+=\d+",
        r"'\s*or\s+'[^']+'\s*=\s*'",
        r"union\s+select",
        r"select\s+.+\s+from\s+",
        r"insert\s+into\s+",
        r"drop\s+table",
        r"--\s*$",
        r";\s*drop",
        r";\s*delete",
        r"'\s*and\s+\d+=\d+",
        r"sleep\s*\(\s*\d+\s*\)",
        r"benchmark\s*\(",
        r"waitfor\s+delay",
        r"'\s*;\s*--",
        r"1\s*=\s*1",
    ],
    "xss": [
        r"<script[\s>]",
        r"</script>",
        r"javascript\s*:",
        r"on\w+\s*=",
        r"<img[^>]+src\s*=\s*['\"]?\s*[xX]",
        r"<svg[\s>]",
        r"<iframe[\s>]",
        r"<body\s+on\w+",
        r"alert\s*\(",
        r"document\.cookie",
        r"document\.location",
        r"eval\s*\(",
        r"<object[\s>]",
        r"expression\s*\(",
    ],
    "traversal": [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"etc/passwd",
        r"etc/shadow",
        r"windows/system32",
        r"boot\.ini",
        r"win\.ini",
        r"proc/self/environ",
        r"\.\.%5c",
        r"\.%2e/",
    ],
    "cmdi": [
        r";\s*cat\s+/",
        r";\s*ls\s",
        r";\s*id\s*$",
        r";\s*whoami",
        r"\|\s*wget\s+",
        r"\|\s*curl\s+",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r";\s*rm\s+-",
        r";\s*chmod\s+",
        r";\s*python\s+",
        r";\s*perl\s+",
        r";\s*bash\s+",
        r"\|\|\s*\w+",
        r"&&\s*\w+",
        r">\s*/etc/",
    ],
}


def check_rules(request_text: str) -> Tuple[Optional[str], bool, Optional[str]]:
    """
    Check normalized request against all rule patterns.
    Returns (attack_label, rule_hit, matched_pattern)
    """
    text = request_text.lower()
    for attack_type, patterns in RULES.items():
        for pattern in patterns:
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    return attack_type, True, pattern
            except re.error:
                continue
    return None, False, None


def get_rule_severity(attack_type: str) -> str:
    return {"sqli": "HIGH", "xss": "HIGH",
            "traversal": "HIGH", "cmdi": "CRITICAL"}.get(attack_type, "MEDIUM")


def get_rule_explanation(attack_type: str) -> str:
    return {
        "sqli":      "SQL Injection: Attempt to manipulate database queries",
        "xss":       "Cross-Site Scripting: Attempt to inject malicious JavaScript",
        "traversal": "Path Traversal: Attempt to access files outside web root",
        "cmdi":      "Command Injection: Attempt to execute system commands",
    }.get(attack_type, "Unknown attack type")


if __name__ == "__main__":
    tests = [
        ("get /search?q=<script>alert(1)</script>", "xss"),
        ("get /item?id=1 union select username,password from users--", "sqli"),
        ("get /files?name=../../etc/passwd", "traversal"),
        ("get /cmd?exec=;cat /etc/passwd", "cmdi"),
        ("get /products?category=electronics", "benign"),
        ("post /login body:username=john&password=pass123", "benign"),
    ]
    print("Rule Engine Tests:")
    print("=" * 60)
    for text, expected in tests:
        label, hit, pattern = check_rules(text)
        got = label or "benign"
        status = "✓" if got == expected else "✗"
        print(f"{status} Expected:{expected:10} Got:{got:10} Pattern:{pattern}")
