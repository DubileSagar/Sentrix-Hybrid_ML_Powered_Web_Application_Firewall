"""
train_distilbert.py
-------------------
Fine-tunes DistilBERT for WAF payload classification.
CPU-optimized settings for Mac (no CUDA required).
Saves model to models_saved/distilbert_waf/
"""

import os
import sys
from pathlib import Path

# Ensure project root is on path
BASE = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

LABEL2ID = {"benign": 0, "sqli": 1, "xss": 2, "traversal": 3, "cmdi": 4}
ID2LABEL = {v: k for k, v in LABEL2ID.items()}

DATA_PATH  = BASE / "data" / "processed" / "augmented_dataset.csv"
SAVE_DIR   = BASE / "models_saved" / "distilbert_waf"


def load_data():
    df = pd.read_csv(DATA_PATH)
    df['request_text'] = df['request_text'].str.strip().str.strip('"')
    df['label'] = df['label'].str.strip().str.lower()
    df = df.dropna(subset=['request_text', 'label'])
    df = df[df['label'].isin(LABEL2ID.keys())]
    df['label_id'] = df['label'].map(LABEL2ID)

    print(f"\n📊 Dataset: {len(df)} samples")
    print(df['label'].value_counts().to_string())

    X, y = df['request_text'].values, df['label_id'].values
    X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    X_val, X_te, y_val, y_te = train_test_split(X_tmp, y_tmp, test_size=0.40, random_state=42, stratify=y_tmp)

    print(f"\nSplit — Train:{len(X_tr)}  Val:{len(X_val)}  Test:{len(X_te)}")
    return X_tr, X_val, X_te, y_tr, y_val, y_te


def train():
    try:
        import torch
        from transformers import (
            DistilBertTokenizerFast,
            DistilBertForSequenceClassification,
            TrainingArguments,
            Trainer,
            EarlyStoppingCallback,
        )
        from torch.utils.data import Dataset
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("   Run: pip install torch transformers")
        sys.exit(1)

    device = torch.device("cpu")
    print(f"\n🖥️  Training on: {device}")

    X_tr, X_val, X_te, y_tr, y_val, y_te = load_data()

    print("\n⬇️  Loading DistilBERT tokenizer from HuggingFace...")
    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

    class WAFDataset(Dataset):
        def __init__(self, texts, labels):
            self.encodings = tokenizer(
                list(texts), max_length=128, padding="max_length",
                truncation=True, return_tensors="pt"
            )
            self.labels = torch.tensor(labels, dtype=torch.long)

        def __len__(self):
            return len(self.labels)

        def __getitem__(self, idx):
            return {
                "input_ids":      self.encodings["input_ids"][idx],
                "attention_mask": self.encodings["attention_mask"][idx],
                "labels":         self.labels[idx],
            }

    print("🔤 Tokenizing datasets...")
    train_ds = WAFDataset(X_tr, y_tr)
    val_ds   = WAFDataset(X_val, y_val)
    test_ds  = WAFDataset(X_te, y_te)
    print("   ✓ Tokenization complete")

    print("\n⬇️  Loading DistilBERT model (distilbert-base-uncased)...")
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=5,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )
    model.to(device)
    print("   ✓ Model loaded")

    os.makedirs(SAVE_DIR, exist_ok=True)
    chk_dir = BASE / "models_saved" / "checkpoints"

    # CPU-optimized training arguments
    args = TrainingArguments(
        output_dir=str(chk_dir),
        num_train_epochs=4,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=32,
        learning_rate=3e-5,
        weight_decay=0.01,
        warmup_ratio=0.1,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        report_to="none",
        logging_steps=20,
        fp16=False,        # Must be False on CPU
        dataloader_num_workers=0,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    print("\n🚀 Training started (this takes ~15-25 min on CPU)...\n")
    trainer.train()

    # ── Evaluation ──────────────────────────────────────────────────────────
    print("\n📈 Evaluating on test set...")
    preds = trainer.predict(test_ds)
    y_pred = np.argmax(preds.predictions, axis=1)
    print("\n" + "="*60)
    print("DISTILBERT TEST RESULTS")
    print("="*60)
    print(classification_report(
        y_te, y_pred,
        target_names=list(LABEL2ID.keys()),
        digits=4
    ))

    # ── Save ────────────────────────────────────────────────────────────────
    print(f"\n💾 Saving model to {SAVE_DIR}...")
    model.save_pretrained(str(SAVE_DIR))
    tokenizer.save_pretrained(str(SAVE_DIR))
    print("✅ DistilBERT model saved successfully!")
    print(f"\n🎯 Ready to use. Restart the WAF API to load DistilBERT:\n")
    print(f"   uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload\n")


if __name__ == "__main__":
    train()
