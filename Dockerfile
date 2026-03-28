FROM python:3.11-slim

WORKDIR /app

# Install dependencies
# (We assume requirements.txt exists and has fastapi, uvicorn, requests, pandas, streamlit, transformers, torch, sqlite3, etc.)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose ports for FastAPI (8000), Streamlit (8501), and Flask (5000)
# Normally these would be separate containers, but for a single monolithic container demo:
EXPOSE 8000 8501 5000

# Script to run all services
RUN echo '#!/bin/bash\n\
uvicorn api.app:app --host 0.0.0.0 --port 8000 &\n\
streamlit run dashboard/streamlit_app.py --server.port 8501 --server.address 0.0.0.0 &\n\
python demo_app/app.py &\n\
wait\n\
' > /app/run_all.sh

RUN chmod +x /app/run_all.sh

CMD ["/app/run_all.sh"]
