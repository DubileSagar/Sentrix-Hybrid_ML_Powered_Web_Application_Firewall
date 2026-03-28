import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from api.app import app

def test_analyze_benign():
    with TestClient(app) as client:
        response = client.post("/analyze", json={
            "method": "GET",
            "path": "/home",
            "headers": {"Host": "localhost"},
            "client_ip": "127.0.0.1"
        })
        print("Benign Response:", response.json())
        assert response.status_code == 200

def test_analyze_malicious():
    with TestClient(app) as client:
        response = client.post("/analyze", json={
            "method": "POST",
            "path": "/login",
            "headers": {"Host": "localhost"},
            "body": "username=admin' OR '1'='1",
            "client_ip": "127.0.0.1"
        })
        print("Malicious Response:", response.json())
        assert response.status_code == 200
        assert response.json()["action"] == "block"

if __name__ == "__main__":
    test_analyze_benign()
    test_analyze_malicious()
    print("All tests passed.")
