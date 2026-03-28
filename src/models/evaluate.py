"""
evaluate.py
-----------
PURPOSE: Deep evaluation beyond accuracy — confusion matrix, 
         false positive rate, baseline vs transformer comparison.

FOR A WAF, FALSE POSITIVE RATE IS THE MOST IMPORTANT METRIC.
FPR = % of legitimate users wrongly blocked. Target: < 2%.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

import numpy as np
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix
from src.models.train import LABEL2ID, ID2LABEL, load_and_prepare_data


def plot_confusion_matrix(y_true, y_pred, title: str, save_path: str = None):
    labels = list(LABEL2ID.keys())
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', xticklabels=labels,
                yticklabels=labels, cmap='Blues', linewidths=0.5)
    plt.title(title, fontsize=14, fontweight='bold')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        print(f"Saved: {save_path}")
    plt.close()


def calculate_false_positive_rate(y_true, y_pred) -> float:
    benign_id = LABEL2ID['benign']
    true_benign = (np.array(y_true) == benign_id)
    fp = ((np.array(y_true) == benign_id) & (np.array(y_pred) != benign_id))
    return float(fp.sum() / true_benign.sum()) if true_benign.sum() > 0 else 0.0


def evaluate_baseline(model_dir: str, data_path: str):
    print("\n" + "="*50 + "\nEVALUATING BASELINE\n" + "="*50)
    tfidf = joblib.load(os.path.join(model_dir, 'tfidf_vectorizer.pkl'))
    clf   = joblib.load(os.path.join(model_dir, 'baseline_classifier.pkl'))
    _, _, X_test, _, _, y_test = load_and_prepare_data(data_path)
    y_pred = clf.predict(tfidf.transform(X_test))
    labels = list(LABEL2ID.keys())
    print(classification_report(y_test, y_pred, target_names=labels))
    fpr = calculate_false_positive_rate(y_test, y_pred)
    print(f"False Positive Rate: {fpr:.2%}")
    plot_confusion_matrix(y_test, y_pred, "Baseline Confusion Matrix",
                          os.path.join(model_dir, 'baseline_cm.png'))
    report = classification_report(y_test, y_pred, target_names=labels,
                                    output_dict=True)
    return {"model": "baseline", "report": report, "fpr": fpr}


def evaluate_transformer(model_dir: str, data_path: str):
    print("\n" + "="*50 + "\nEVALUATING TRANSFORMER\n" + "="*50)
    model_path = os.path.join(model_dir, 'distilbert_waf')
    if not os.path.exists(model_path):
        print("Transformer not found. Train first.")
        return None
    try:
        import torch, torch.nn.functional as F
        from transformers import (DistilBertTokenizer,
                                   DistilBertForSequenceClassification)
    except ImportError:
        print("PyTorch not installed.")
        return None

    device    = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    tokenizer = DistilBertTokenizer.from_pretrained(model_path)
    model     = DistilBertForSequenceClassification.from_pretrained(model_path)
    model.to(device)
    model.eval()

    _, _, X_test, _, _, y_test = load_and_prepare_data(data_path)
    y_pred, batch_size = [], 32

    for i in range(0, len(X_test), batch_size):
        batch = list(X_test[i:i+batch_size])
        inputs = tokenizer(batch, max_length=128, padding=True,
                           truncation=True, return_tensors='pt')
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            logits = model(**inputs).logits
        y_pred.extend(torch.argmax(F.softmax(logits, dim=-1),
                                    dim=1).cpu().numpy().tolist())

    labels = list(LABEL2ID.keys())
    print(classification_report(y_test, y_pred, target_names=labels))
    fpr = calculate_false_positive_rate(y_test, y_pred)
    print(f"False Positive Rate: {fpr:.2%}")
    plot_confusion_matrix(y_test, y_pred, "Transformer Confusion Matrix",
                          os.path.join(model_dir, 'transformer_cm.png'))
    report = classification_report(y_test, y_pred, target_names=labels,
                                    output_dict=True)
    return {"model": "distilbert", "report": report, "fpr": fpr}


def compare_models(b, t):
    if not b or not t:
        return
    print("\n" + "="*50 + "\nMODEL COMPARISON\n" + "="*50)
    print(f"\n{'Label':<12} {'Baseline F1':>12} {'DistilBERT F1':>14}")
    print("-" * 40)
    for label in LABEL2ID.keys():
        bf = b['report'].get(label, {}).get('f1-score', 0)
        tf = t['report'].get(label, {}).get('f1-score', 0)
        arrow = "↑" if tf > bf else ("↓" if tf < bf else "=")
        print(f"{label:<12} {bf:>12.3f} {tf:>14.3f} {arrow}")
    print(f"\nBaseline FPR:    {b['fpr']:.2%}")
    print(f"Transformer FPR: {t['fpr']:.2%}")


if __name__ == "__main__":
    data_path = "data/processed/augmented_dataset.csv"
    model_dir = "models_saved"
    br = evaluate_baseline(model_dir, data_path)
    tr = evaluate_transformer(model_dir, data_path)
    compare_models(br, tr)
