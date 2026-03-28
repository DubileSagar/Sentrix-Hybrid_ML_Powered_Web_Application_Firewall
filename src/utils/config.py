import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Paths configuration
DB_PATH = BASE_DIR / "logs" / "waf_logs.db"
MODEL_PATH = BASE_DIR / "models_saved" / "distilbert_waf"

# App settings
DEBUG = True
