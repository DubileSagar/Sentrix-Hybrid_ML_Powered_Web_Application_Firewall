"""
infer.py
--------
PURPOSE: Load trained models ONCE at startup, reuse for every request.

DistilBERT is the ONLY ML engine. No baseline fallback.
Loading DistilBERT from disk takes 5-10 seconds.
Loading once at startup = ~50ms inference per request.
"""

import os
import numpy as np
from typing import Tuple, Dict
from src.models.train import LABEL2ID, ID2LABEL

_transformer_model     = None
_transformer_tokenizer = None
_device                = None

# Keep baseline for legacy support but do NOT use in predict() by default
_baseline_tfidf = None
_baseline_clf   = None


def load_baseline_model(model_dir: str = "models_saved"):
    global _baseline_tfidf, _baseline_clf
    import joblib
    tfidf_path = os.path.join(model_dir, 'tfidf_vectorizer.pkl')
    clf_path   = os.path.join(model_dir, 'baseline_classifier.pkl')
    if os.path.exists(tfidf_path) and os.path.exists(clf_path):
        _baseline_tfidf = joblib.load(tfidf_path)
        _baseline_clf   = joblib.load(clf_path)
        print(f"✓ Baseline model loaded from {model_dir} (standby — DistilBERT preferred)")
    else:
        print(f"⚠ Baseline model not found at {model_dir} (not required)")


def load_transformer_model(model_dir: str = "models_saved") -> bool:
    global _transformer_model, _transformer_tokenizer, _device
    try:
        import torch
        from transformers import (DistilBertTokenizerFast,
                                   DistilBertForSequenceClassification)
        model_path = os.path.join(model_dir, 'distilbert_waf')
        if not os.path.exists(model_path):
            print(f"❌ FATAL: DistilBERT not found at {model_path}.")
            print("   Train first:  python scripts/train_distilbert.py")
            return False
        _device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        _transformer_tokenizer = DistilBertTokenizerFast.from_pretrained(model_path)
        _transformer_model = DistilBertForSequenceClassification.from_pretrained(model_path)
        _transformer_model.to(_device)
        _transformer_model.eval()
        print(f"✅ DistilBERT loaded successfully ({_device})")
        return True
    except ImportError:
        print("❌ PyTorch not installed. Cannot load DistilBERT.")
        return False


def is_distilbert_ready() -> bool:
    return _transformer_model is not None


def predict_transformer(request_text: str) -> Tuple[str, float, Dict]:
    """Run a request through DistilBERT. Returns (label, confidence, all_probs)."""
    if _transformer_model is None:
        raise RuntimeError(
            "DistilBERT is not loaded. "
            "Run: python scripts/train_distilbert.py  then restart the API."
        )
    try:
        import torch
        import torch.nn.functional as F
        inputs = _transformer_tokenizer(
            request_text, max_length=128, padding='max_length',
            truncation=True, return_tensors='pt')
        inputs = {k: v.to(_device) for k, v in inputs.items()}
        with torch.no_grad():
            logits = _transformer_model(**inputs).logits
        probs = F.softmax(logits, dim=-1)[0]
        idx   = int(torch.argmax(probs).item())
        conf  = float(probs[idx].item())
        all_probs = {ID2LABEL[i]: round(float(probs[i].item()), 4)
                     for i in range(len(LABEL2ID))}
        return ID2LABEL[idx], conf, all_probs
    except Exception as e:
        raise RuntimeError(f"DistilBERT inference error: {e}")


def predict(request_text: str, use_transformer: bool = True) -> Dict:
    """
    Always uses DistilBERT. Raises RuntimeError if DistilBERT is not loaded.
    """
    label, conf, all_probs = predict_transformer(request_text)
    return {
        "predicted_label":   label,
        "confidence":        round(conf, 4),
        "all_probabilities": all_probs,
        "model_used":        "distilbert",
    }


if __name__ == "__main__":
    print("Loading DistilBERT...")
    if not load_transformer_model("models_saved"):
        print("Model not found. Train first: python scripts/train_distilbert.py")
        exit(1)

    tests = [
        "GET /search?q=<script>alert(1)</script> HTTP/1.1",
        "POST /login HTTP/1.1\n\nusername=admin' OR 1=1--&password=x",
        "GET /files?file=../../../../etc/passwd HTTP/1.1",
        "GET /ping?host=localhost;cat /etc/shadow HTTP/1.1",
        "GET /products?category=electronics HTTP/1.1",
    ]
    print("\nDistilBERT Predictions:")
    for req in tests:
        r = predict(req)
        bar = "█" * int(r['confidence'] * 20)
        print(f"  [{r['predicted_label']:10}] {r['confidence']:.0%} {bar}  {req[:55]}")
