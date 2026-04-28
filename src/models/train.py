"""
train.py
--------
PURPOSE: Train two models and save them.
1. TF-IDF + Logistic Regression (baseline — fast, explainable)
2. DistilBERT fine-tuned classifier (main model — contextual, accurate)

WHY TWO MODELS:
The baseline lets you say "DistilBERT achieved X% vs Y% for TF-IDF baseline"
in interviews. That comparison is what shows real ML thinking.
"""

import os
import pandas as pd
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

LABEL2ID = {"benign": 0, "sqli": 1, "xss": 2, "traversal": 3, "cmdi": 4}
ID2LABEL = {v: k for k, v in LABEL2ID.items()}


def load_and_prepare_data(data_path: str):
    df = pd.read_csv(data_path)
    df['request_text'] = df['request_text'].str.strip().str.strip('"')
    df['label'] = df['label'].str.strip().str.lower()
    df = df.dropna(subset=['request_text', 'label'])
    df = df[df['label'].isin(LABEL2ID.keys())]
    df['label_id'] = df['label'].map(LABEL2ID)

    print(f"Total samples: {len(df)}")
    print(f"Distribution:\n{df['label'].value_counts()}\n")

    X, y = df['request_text'].values, df['label_id'].values
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    print(f"Train:{len(X_train)} Val:{len(X_val)} Test:{len(X_test)}")
    return X_train, X_val, X_test, y_train, y_val, y_test


def train_baseline(X_train, X_val, X_test, y_train, y_val, y_test, save_dir):
    print("\n" + "="*50)
    print("TRAINING BASELINE: TF-IDF + Logistic Regression")
    print("="*50)

    # char_wb analyzer: looks at character n-grams (2-5 chars)
    # Better for attack detection than word-level features
    tfidf = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 5),
                            max_features=50000, sublinear_tf=True)
    X_train_t = tfidf.fit_transform(X_train)
    X_val_t   = tfidf.transform(X_val)
    X_test_t  = tfidf.transform(X_test)

    clf = LogisticRegression(C=1.0, class_weight='balanced',
                             max_iter=1000, random_state=42,
                             multi_class='multinomial', solver='lbfgs')
    clf.fit(X_train_t, y_train)

    print("\nValidation:")
    print(classification_report(y_val, clf.predict(X_val_t),
                                 target_names=list(LABEL2ID.keys())))
    print("Test:")
    print(classification_report(y_test, clf.predict(X_test_t),
                                 target_names=list(LABEL2ID.keys())))

    os.makedirs(save_dir, exist_ok=True)
    joblib.dump(tfidf, os.path.join(save_dir, 'tfidf_vectorizer.pkl'))
    joblib.dump(clf,   os.path.join(save_dir, 'baseline_classifier.pkl'))
    print(f"Baseline saved to {save_dir}")
    return tfidf, clf


def train_transformer(X_train, X_val, X_test, y_train, y_val, y_test, save_dir):
    print("\n" + "="*50)
    print("TRAINING TRANSFORMER: DistilBERT")
    print("="*50)
    try:
        import torch
        from transformers import (DistilBertTokenizer,
                                   DistilBertForSequenceClassification,
                                   TrainingArguments, Trainer,
                                   EarlyStoppingCallback)
        from torch.utils.data import Dataset
    except ImportError:
        print("PyTorch/Transformers not installed.")
        return None, None

    tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')

    class WAFDataset(Dataset):
        def __init__(self, texts, labels):
            self.encodings = tokenizer(list(texts), max_length=128,
                                       padding='max_length', truncation=True,
                                       return_tensors='pt')
            self.labels = torch.tensor(labels, dtype=torch.long)
        def __len__(self): return len(self.labels)
        def __getitem__(self, idx):
            return {'input_ids':      self.encodings['input_ids'][idx],
                    'attention_mask': self.encodings['attention_mask'][idx],
                    'labels':         self.labels[idx]}

    model = DistilBertForSequenceClassification.from_pretrained(
        'distilbert-base-uncased', num_labels=5,
        id2label=ID2LABEL, label2id=LABEL2ID)

    os.makedirs(save_dir, exist_ok=True)
    args = TrainingArguments(
        output_dir=os.path.join(save_dir, 'checkpoints'),
        num_train_epochs=5, per_device_train_batch_size=16,
        per_device_eval_batch_size=32, learning_rate=2e-5,
        weight_decay=0.01, eval_strategy='epoch',
        save_strategy='epoch', load_best_model_at_end=True,
        metric_for_best_model='eval_loss', report_to='none',
        logging_steps=10)

    trainer = Trainer(
        model=model, args=args,
        train_dataset=WAFDataset(X_train, y_train),
        eval_dataset=WAFDataset(X_val, y_val),
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)])

    trainer.train()

    preds = trainer.predict(WAFDataset(X_test, y_test))
    y_pred = np.argmax(preds.predictions, axis=1)
    print("\nTest Results:")
    print(classification_report(y_test, y_pred,
                                 target_names=list(LABEL2ID.keys())))

    final_path = os.path.join(save_dir, 'distilbert_waf')
    model.save_pretrained(final_path)
    tokenizer.save_pretrained(final_path)
    print(f"Transformer saved to {final_path}")
    return model, tokenizer


if __name__ == "__main__":
    data_path = "data/processed/augmented_dataset.csv"
    if not os.path.exists(data_path):
        print("Run augmentor.py first.")
    else:
        splits = load_and_prepare_data(data_path)
        train_baseline(*splits, "models_saved")
        train_transformer(*splits, "models_saved")
