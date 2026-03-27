"""
decision_engine.py
------------------
PURPOSE: Combine rule engine + ML outputs into a final allow/block/flag decision.

DECISION LOGIC:
1. Rule hit                     -> BLOCK  (rules are high precision)
2. ML malicious, conf >= 0.90   -> BLOCK  (very confident attack)
3. ML malicious, conf >= 0.65   -> FLAG   (suspicious, allow but log)
4. Everything else              -> ALLOW

WHY THRESHOLDS:
False positives (blocking real users) are costly.
We use conservative thresholds and prefer flagging over blocking when unsure.
"""

from typing import Optional, Dict

BLOCK_THRESHOLD = 0.90
FLAG_THRESHOLD  = 0.65


def decide(rule_hit: bool, rule_label: Optional[str],
           ml_label: str, ml_confidence: float,
           matched_pattern: Optional[str] = None) -> Dict:
    """
    Make the final allow/block/flag decision.
    Returns dict with: action, final_label, reason, confidence, decision_type
    """
    if rule_hit and rule_label is not None:
        return {"action": "block", "final_label": rule_label,
                "reason": f"Rule matched: {matched_pattern}",
                "confidence": 1.0, "decision_type": "rule_based"}

    if ml_label != "benign" and ml_confidence >= BLOCK_THRESHOLD:
        return {"action": "block", "final_label": ml_label,
                "reason": f"ML detected {ml_label} ({ml_confidence:.1%} confidence)",
                "confidence": ml_confidence, "decision_type": "ml_block"}

    if ml_label != "benign" and ml_confidence >= FLAG_THRESHOLD:
        return {"action": "flag", "final_label": ml_label,
                "reason": f"ML flagged {ml_label} ({ml_confidence:.1%} — below block threshold)",
                "confidence": ml_confidence, "decision_type": "ml_flag"}

    return {"action": "allow", "final_label": ml_label,
            "reason": f"No threat detected (conf: {ml_confidence:.1%})",
            "confidence": ml_confidence, "decision_type": "allowed"}


def get_http_response_code(action: str) -> int:
    return {"block": 403, "flag": 200, "allow": 200}.get(action, 200)


def get_action_description(action: str, label: str, confidence: float) -> str:
    return {
        "block": f"BLOCKED. Detected {label} ({confidence:.1%} confidence).",
        "flag":  f"FLAGGED. Possible {label} ({confidence:.1%}). Allowed but logged.",
        "allow": "ALLOWED. No threat detected.",
    }.get(action, "Unknown action")


if __name__ == "__main__":
    cases = [
        (True,  "xss",  "xss",    0.97, "<script[\\s>]"),
        (False, None,   "sqli",   0.93, None),
        (False, None,   "sqli",   0.72, None),
        (False, None,   "sqli",   0.45, None),
        (False, None,   "benign", 0.98, None),
    ]
    print("Decision Engine Tests:")
    for args in cases:
        r = decide(*args)
        print(f"  action={r['action']:6}  label={r['final_label']:10}  {r['reason']}")
