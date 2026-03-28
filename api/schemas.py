from pydantic import BaseModel, Field
from typing import Dict, Optional

class RequestPayload(BaseModel):
    method: str = Field(..., json_schema_extra={"example": "GET"})
    path: str = Field(..., json_schema_extra={"example": "/login?user=admin"})
    headers: Dict[str, str] = Field(default_factory=dict, json_schema_extra={"example": {"Host": "example.com"}})
    body: str = Field(default="", json_schema_extra={"example": ""})
    client_ip: str = Field(..., json_schema_extra={"example": "192.168.1.5"})

class WAFDecision(BaseModel):
    action: str = Field(..., json_schema_extra={"example": "block"})
    final_label: str = Field(..., json_schema_extra={"example": "sqli"})
    reason: str = Field(..., json_schema_extra={"example": "Rule matched: union select"})
    confidence: float = Field(..., json_schema_extra={"example": 1.0})
    rule_matched: Optional[str] = Field(None, json_schema_extra={"example": "union select"})
