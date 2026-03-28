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

@app.on_event("startup")
async def startup_event():
    print("Initializing Sentrix WAF Models...")
    try:
        load_baseline_model()
    except Exception as e:
        print(f"Failed to load baseline model: {e}")
    
    try:
        load_transformer_model()
    except Exception as e:
        print(f"Failed to load transformer model: {e}")

@app.post("/analyze", response_model=WAFDecision)
async def analyze_request(payload: RequestPayload):
    # 1. Reconstruct raw request string for the parser/formatter
    raw_req = f"{payload.method} {payload.path} HTTP/1.1\n"
    for k, v in payload.headers.items():
        raw_req += f"{k}: {v}\n"
    if payload.body:
        raw_req += f"\nBody: {payload.body}"
        
    # 2. Format request
    formatted_req = format_request(raw_req)
    
    # 3. Rule Engine
    rule_label, rule_hit, matched_pattern = check_rules(formatted_req)
    
    # 4. ML Model (Optimizaton: skip ML if rule hits and blocks with 100% confidence)
    if rule_hit:
        ml_label = "benign"
        ml_confidence = 0.0
    else:
        try:
            ml_pred = predict(formatted_req)
            ml_label = ml_pred.get("predicted_label", "benign")
            ml_confidence = ml_pred.get("confidence", 0.0)
        except RuntimeError:
            print("Warning: ML models not loaded. Bypassing ML inspection.")
            ml_label = "benign"
            ml_confidence = 0.0
            
    # 5. Decision Engine
    decision = decide(
        rule_hit=rule_hit,
        rule_label=rule_label,
        ml_label=ml_label,
        ml_confidence=ml_confidence,
        matched_pattern=matched_pattern
    )
    
    # 6. Log Decision
    request_data = {
        "client_ip": payload.client_ip,
        "method": payload.method,
        "path": payload.path,
        "headers": payload.headers,
        "body": payload.body
    }
    log_request(request_data, decision)
    
    # 7. Return Response
    reason_str = decision.get("reason", "")
    rule_matched_str = matched_pattern if rule_hit else None

    return WAFDecision(
        action=decision.get("action", "allow"),
        final_label=decision.get("final_label", "benign"),
        reason=reason_str,
        confidence=decision.get("confidence", 0.0),
        rule_matched=rule_matched_str
    )
