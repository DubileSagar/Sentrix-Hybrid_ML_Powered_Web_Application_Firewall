#!/bin/bash
source .venv/bin/activate
uvicorn api.app:app --host 0.0.0.0 --port 8000 &
python demo_app/app.py &
wait
