"""
infer.py
--------
PURPOSE: Load trained models ONCE at startup, reuse for every request.

WHY NOT LOAD INSIDE THE PREDICT FUNCTION:
Loading DistilBERT from disk takes 5-10 seconds.
If we loaded per-request, the WAF would be unusably slow.
Loading once at startup = ~50ms inference per request.
"""

import os
import numpy as np
from typing import Tuple, Dict
from src.models.train import LABEL2ID, ID2LABEL

_baseline_tfidf      = None
_baseline_clf        = None
_transformer_model   = None
_transformer_tokenizer = None
_device              = None


def load_baseline_model(model_dir: str = "models_saved"):
    global _baseline_tfidf, _baseline_clf
    import joblib
    tfidf_path = os.path.join(model_dir, 'tfidf_vectorizer.pkl')
    clf_path   = os.path.join(model_dir, 'baseline_classifier.pkl')
    if not os.path.exists(tfidf_path):
        raise FileNotFoundError(f"Baseline model not found at {model_dir}")
    _baseline_tfidf = joblib.load(tfidf_path)
    _baseline_clf   = joblib.load(clf_path)
    print(f"✓ Baseline model loaded from {model_dir}")


def load_transformer_model(model_dir: str = "models_saved") -> bool:
    global _transformer_model, _transformer_tokenizer, _device
    try:
        import torch
        from transformers import (DistilBertTokenizer,
                                   DistilBertForSequenceClassification)
        model_path = os.path.join(model_dir, 'distilbert_waf')
        if not os.path.exists(model_path):
            print(f"⚠ Transformer not found at {model_path}. Using baseline only.")
            return False
        _device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        _transformer_tokenizer = DistilBertTokenizer.from_pretrained(model_path)
        _transformer_model = DistilBertForSequenceClassification.from_pretrained(
            model_path)
        _transformer_model.to(_device)
        _transformer_model.eval()
        print(f"✓ Transformer loaded ({_device})")
        return True
    except ImportError:
        print("⚠ PyTorch not installed. Using baseline only.")
        return False


def predict_baseline(request_text: str) -> Tuple[str, float]:
    if _baseline_tfidf is None:
        raise RuntimeError("Baseline not loaded. Call load_baseline_model() first.")
    features = _baseline_tfidf.transform([request_text])
    probs = _baseline_clf.predict_proba(features)[0]
    idx = int(np.argmax(probs))
    return ID2LABEL[idx], float(probs[idx])


def predict_transformer(request_text: str) -> Tuple[str, float, Dict]:
    if _transformer_model is None:
        label, conf = predict_baseline(request_text)
        return label, conf, {}
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
        all_probs = {ID2LABEL[i]: float(probs[i].item())
                     for i in range(len(LABEL2ID))}
        return ID2LABEL[idx], conf, all_probs
    except Exception as e:
        print(f"Transformer error: {e}. Falling back to baseline.")
        label, conf = predict_baseline(request_text)
        return label, conf, {}


def predict(request_text: str, use_transformer: bool = True) -> Dict:
    if use_transformer and _transformer_model is not None:
        label, conf, all_probs = predict_transformer(request_text)
        model_used = "distilbert"
    else:
        label, conf = predict_baseline(request_text)
        all_probs  = {}
        model_used = "baseline_tfidf"
    return {"predicted_label": label, "confidence": round(conf, 4),
            "all_probabilities": all_probs, "model_used": model_used}


if __name__ == "__main__":
    print("Loading models...")
    try:
        load_baseline_model("models_saved")
        load_transformer_model("models_saved")
    except FileNotFoundError as e:
        print(f"Error: {e}\nTrain models first: python src/models/train.py")
        exit(1)
    tests = [
        "get /search?q=<script>alert(1)</script>",
        "get /item?id=1 union select password from users--",
        "get /files?name=../../etc/passwd",
        "get /ping?host=127.0.0.1;cat /etc/passwd",
        "get /products?category=electronics",
        "post /login body:username=john&password=pass123",
    ]
    print("\nPredictions:")
    for req in tests:
        r = predict(req)
        print(f"  {req[:50]:<50} -> {r['predicted_label']:10} ({r['confidence']:.0%})")
