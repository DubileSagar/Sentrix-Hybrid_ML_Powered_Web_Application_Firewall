import sqlite3
import json
from typing import Dict, Any
from src.utils.config import DB_PATH

def init_db():
    """Initialize the SQLite database and create the requests table if it doesn't exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            method TEXT,
            path TEXT,
            headers TEXT,
            body TEXT,
            action TEXT,
            final_label TEXT,
            rule_matched TEXT,
            ml_confidence REAL,
            decision_reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_request(request_data: Dict[str, Any], decision: Dict[str, Any]):
    """
    Log an HTTP request and its WAF decision into the SQLite database.
    
    Args:
        request_data (Dict): Contains client_ip, method, path, headers, body
        decision (Dict): Contains action, final_label, reason, confidence
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    headers_str = json.dumps(request_data.get("headers", {}))
    
    # Extract rule info if this was a rule-based decision
    reason = decision.get("reason", "")
    rule_matched = None
    if "Rule matched" in reason:
        rule_matched = reason
    
    cursor.execute('''
        INSERT INTO requests (
            client_ip, method, path, headers, body,
            action, final_label, rule_matched, ml_confidence, decision_reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        request_data.get("client_ip", ""),
        request_data.get("method", ""),
        request_data.get("path", ""),
        headers_str,
        request_data.get("body", ""),
        decision.get("action", "allow"),
        decision.get("final_label", "benign"),
        rule_matched,
        decision.get("confidence", 0.0),
        reason
    ))
    conn.commit()
    conn.close()

# Ensure the database is initialized when the module is imported
init_db()

if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
    log_request(
        {
            "client_ip": "127.0.0.1", 
            "method": "GET", 
            "path": "/test", 
            "headers": {"User-Agent": "curl"}, 
            "body": ""
        },
        {
            "action": "allow", 
            "final_label": "benign", 
            "confidence": 0.99, 
            "reason": "No threat detected"
        }
    )
    print("Test log inserted successfully. Database logic passes!")
