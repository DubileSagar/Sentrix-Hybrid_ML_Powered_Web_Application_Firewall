import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.schemas import RequestPayload, WAFDecision
from src.preprocessing.formatter import format_request
from src.rules.rule_engine import check_rules
from src.models.infer import load_baseline_model, load_transformer_model, predict
from src.models.decision_engine import decide
from src.logging_system.logger import log_request

app = FastAPI(title="Sentrix WAF API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Removed root /docs redirect so the Reverse Proxy handles the base path.

@app.on_event("startup")
async def startup_event():
    print("\n" + "="*55)
    print("  Sentrix WAF — Initializing DistilBERT Engine")
    print("="*55)
    # Load baseline as warm standby (not used for inference)
    try:
        load_baseline_model()
    except Exception:
        pass
    # DistilBERT is the primary (and only) ML engine
    ok = load_transformer_model()
    if not ok:
        print("\n⚠  WARNING: DistilBERT NOT LOADED.")
        print("   WAF will use rule-based engine only until model is trained.")
        print("   Train now:  python scripts/train_distilbert.py\n")
    else:
        print("\n✅ Sentrix WAF is LIVE — DistilBERT engine active.\n")

import httpx
from fastapi import Request, Response, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, StreamingResponse
import os
import json
import asyncio
import sqlite3
import csv
import io
from datetime import datetime, timedelta
from src.utils.config import DB_PATH

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                pass

manager = ConnectionManager()

# Target backend application (the vulnerable demo app)
TARGET_URL = os.getenv("TARGET_URL", "http://127.0.0.1:5001")

BLOCK_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden - Threat Intercepted</title>
    <style>
        body { 
            font-family: 'Courier New', Courier, monospace; 
            background-color: #0b0f19; color: #ff3366; 
            margin: 0; height: 100vh; display: flex; 
            align-items: center; justify-content: center;
            background-image: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255, 51, 102, 0.03) 2px, rgba(255, 51, 102, 0.03) 4px);
        }
        .container { 
            background: rgba(20, 25, 40, 0.8); padding: 50px; 
            border: 2px solid #ff3366; border-radius: 8px; 
            text-align: center; box-shadow: 0 0 40px rgba(255, 51, 102, 0.3), inset 0 0 20px rgba(255, 51, 102, 0.1); 
            max-width: 600px; width: 90%;
            animation: pulse-border 2s infinite;
        }
        @keyframes pulse-border {
            0% { box-shadow: 0 0 40px rgba(255, 51, 102, 0.3); }
            50% { box-shadow: 0 0 60px rgba(255, 51, 102, 0.6); }
            100% { box-shadow: 0 0 40px rgba(255, 51, 102, 0.3); }
        }
        h1 { font-size: 3rem; margin-top: 0; text-transform: uppercase; text-shadow: 0 0 10px #ff3366; }
        .reason-box { background: rgba(0,0,0,0.5); color: #fff; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px dashed #ff3366; font-size: 1.1rem;}
        a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: transparent; color: #ff3366; text-decoration: none; border: 1px solid #ff3366; font-weight: bold; transition: 0.3s; text-transform: uppercase;}
        a:hover { background: #ff3366; color: #000; box-shadow: 0 0 15px #ff3366; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠ THREAT INTERCEPTED</h1>
        <h2>403 Forbidden</h2>
        <p>Your request was flagged as malicious and terminated by Sentrix WAF.</p>
        <div class="reason-box">Matched Signature: <b>{reason}</b></div>
        <a href="javascript:history.back()">&lt; Return to Safety</a>
    </div>
</body>
</html>
"""

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from client, but keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/dashboard", include_in_schema=False)
async def serve_dashboard():
    dashboard_path = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text())
    return HTMLResponse(content="<h1>Dashboard UI file missing.</h1>", status_code=404)

import sqlite3
from src.utils.config import DB_PATH

@app.get("/api/stats")
async def get_stats():
    """Fetches historical count from SQLite for persistent dashboard."""
    if not DB_PATH.exists():
        return {"total": 0, "allow": 0, "block": 0, "flag": 0}
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT action, COUNT(*) FROM requests GROUP BY action")
        rows = cursor.fetchall()
        conn.close()
        
        stats = {"total": 0, "allow": 0, "block": 0, "flag": 0}
        for row in rows:
            action, count = row
            stats[action] = count
            stats["total"] += count
        return stats
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return {"total": 0, "allow": 0, "block": 0, "flag": 0}

# /analyze endpoint — used by Payload Tester and external scripts
@app.post("/analyze", response_model=WAFDecision)
async def analyze_request_legacy(payload: RequestPayload):
    raw_req = f"{payload.method} {payload.path} HTTP/1.1\n"
    for k, v in payload.headers.items(): raw_req += f"{k}: {v}\n"
    if payload.body: raw_req += f"\nBody: {payload.body}"

    formatted_req = format_request(raw_req)
    rule_label, rule_hit, matched_pattern = check_rules(formatted_req)

    ml_label, ml_confidence, all_probs, model_used = "benign", 0.0, {}, "rule_engine"
    if rule_hit:
        model_used = "rule_engine"
    else:
        try:
            ml_pred   = predict(formatted_req)
            ml_label  = ml_pred.get("predicted_label", "benign")
            ml_confidence = ml_pred.get("confidence", 0.0)
            all_probs = ml_pred.get("all_probabilities", {})
            model_used = ml_pred.get("model_used", "distilbert")
        except RuntimeError:
            pass

    decision = decide(rule_hit=rule_hit, rule_label=rule_label, ml_label=ml_label,
                      ml_confidence=ml_confidence, matched_pattern=matched_pattern)
    request_data = {"client_ip": payload.client_ip, "method": payload.method,
                    "path": payload.path, "headers": payload.headers, "body": payload.body}
    log_request(request_data, decision)
    return WAFDecision(
        action=decision.get("action", "allow"),
        final_label=decision.get("final_label", "benign"),
        reason=decision.get("reason", ""),
        confidence=decision.get("confidence", 0.0),
        rule_matched=matched_pattern if rule_hit else None,
        model_used=model_used,
        all_probabilities=all_probs,
    )

@app.get("/api/export-logs")
async def export_logs(
    timeframe: str = Query(None),
    start_date: str = Query(None),
    end_date: str = Query(None)
):
    query = "SELECT timestamp, client_ip, method, path, action, final_label, ml_confidence, decision_reason FROM requests WHERE 1=1"
    params = []
    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date.replace("T", " "))
    if end_date:
        query += " AND timestamp <= ?"
        params.append(end_date.replace("T", " "))
    if not start_date and not end_date:
        if timeframe == "24h": query += " AND timestamp >= datetime('now', '-1 day')"
        elif timeframe == "7d": query += " AND timestamp >= datetime('now', '-7 days')"
        elif timeframe == "30d": query += " AND timestamp >= datetime('now', '-30 days')"
        elif timeframe == "this_month": query += " AND timestamp >= date('now', 'start of month')"
        elif timeframe == "last_month": query += " AND timestamp >= date('now', 'start of month', '-1 month') AND timestamp < date('now', 'start of month')"
        elif timeframe == "this_year": query += " AND timestamp >= date('now', 'start of year')"
        elif timeframe == "last_year": query += " AND timestamp >= date('now', 'start of year', '-1 year') AND timestamp < date('now', 'start of year')"
    
    query += " ORDER BY timestamp DESC"
    def generate_csv():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Timestamp", "IP Address", "Method", "Path", "Action", "Label", "Confidence", "Reason"])
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query, params)
        while True:
            rows = cursor.fetchmany(100)
            if not rows: break
            for row in rows: writer.writerow(row)
            data = output.getvalue()
            output.truncate(0); output.seek(0)
            yield data
        conn.close()
    filename = f"sentrix_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(generate_csv(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})

from fastapi import File, UploadFile
import csv
import io

@app.post("/api/scan-logs")
async def scan_logs(file: UploadFile = File(...)):
    """Reads a CSV file line by line and simulates WAF inspection on it."""
    results = {"allow": [], "flag": [], "block": []}
    
    contents = await file.read()
    try:
        # Assuming CSV format: method, path, headers (json string), body
        # For simplicity, if it's just raw strings, we treat the whole line as a path
        text_content = contents.decode('utf-8')
        reader = csv.reader(text_content.splitlines())
        
        for num, row in enumerate(reader):
            if not row: continue
            
            # Support custom_payloads.csv (3 cols: type, location, payload)
            # Treat the last column as the raw payload for WAF checking.
            raw_target = row[-1].strip() if len(row) > 0 else str(row)
            if not raw_target: continue
            
            formatted_req = format_request(raw_target)
            rule_label, rule_hit, matched_pattern = check_rules(formatted_req)
            
            if rule_hit:
                ml_label, ml_confidence = "benign", 0.0
            else:
                try:
                    ml_pred = predict(formatted_req)
                    ml_label = ml_pred.get("predicted_label", "benign")
                    ml_confidence = ml_pred.get("confidence", 0.0)
                except:
                    ml_label, ml_confidence = "benign", 0.0
                    
            decision = decide(rule_hit=rule_hit, rule_label=rule_label, ml_label=ml_label, ml_confidence=ml_confidence, matched_pattern=matched_pattern)
            action = decision.get("action", "allow")
            # Safe-guard: unknown action keys fall back to allow
            if action not in results:
                action = "allow"
            
            results[action].append({
                "line": num + 1,
                "payload": raw_target[:120],
                "final_label": decision.get("final_label", "benign"),
                "reason": decision.get("reason", "")
            })
            
        return {"status": "success", "results": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}



@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"], include_in_schema=False)
async def reverse_proxy(request: Request, path: str):
    # Explicitly bypass reverse proxy for internal routes
    if path.startswith("api/") or path.startswith("ws/") or path == "dashboard" or path == "favicon.ico":
         return Response(status_code=404) # Fallback if specific routes above didn't catch it

    client_ip = request.client.host if request.client else "127.0.0.1"
    
    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8', errors='ignore')
    
    headers_dict = dict(request.headers)
    # Remove Host header so httpx populates it correctly for the target.
    headers_dict.pop("host", None)
    
    # Include full URL with query string so GET params like ?file=../../../../etc/passwd are inspected
    full_path = request.url.path
    if request.url.query:
        full_path += f"?{request.url.query}"
    raw_req = f"{request.method} {full_path} HTTP/1.1\n"
    for k, v in headers_dict.items():
        raw_req += f"{k}: {v}\n"
    if body_str:
        raw_req += f"\nBody: {body_str}"
        
    formatted_req = format_request(raw_req)
    rule_label, rule_hit, matched_pattern = check_rules(formatted_req)

    ml_label, ml_confidence, model_used = "benign", 0.0, "rule_engine"
    if not rule_hit:
        try:
            ml_pred = predict(formatted_req)
            ml_label  = ml_pred.get("predicted_label", "benign")
            ml_confidence = ml_pred.get("confidence", 0.0)
            model_used = ml_pred.get("model_used", "distilbert")
        except RuntimeError:
            pass

    decision = decide(rule_hit=rule_hit, rule_label=rule_label, ml_label=ml_label,
                      ml_confidence=ml_confidence, matched_pattern=matched_pattern)
    request_data = {"client_ip": client_ip, "method": request.method,
                    "path": request.url.path, "headers": headers_dict, "body": body_str}
    log_request(request_data, decision)

    # Broadcast to dashboard (includes model_used)
    broadcast_data = {
        "timestamp":   decision.get("timestamp", "Now"),
        "client_ip":   client_ip,
        "method":      request.method,
        "path":        request.url.path,
        "action":      decision.get("action", "allow"),
        "final_label": decision.get("final_label", "benign"),
        "reason":      decision.get("reason", ""),
        "model_used":  model_used,
    }
    asyncio.create_task(manager.broadcast(broadcast_data))

    if decision.get("action") == "block":
        return HTMLResponse(content=BLOCK_HTML.format(reason=decision.get("reason", "Malicious Payload Detected")), status_code=403)

    # Forward to target server
    target_url = f"{TARGET_URL}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"
        
    async with httpx.AsyncClient() as client:
        try:
            proxy_req = client.build_request(
                method=request.method,
                url=target_url,
                headers=headers_dict,
                content=body_bytes,
                timeout=10.0
            )
            proxy_resp = await client.send(proxy_req)
            
            return Response(
                content=proxy_resp.content,
                status_code=proxy_resp.status_code,
                headers=dict(proxy_resp.headers)
            )
        except httpx.RequestError as exc:
            return HTMLResponse(content=f"<h3>502 Bad Gateway</h3><p>Sentrix WAF cannot reach origin server at {TARGET_URL}. Detailed Error: {exc}</p>", status_code=502)
