"""
augmentor.py
------------
PURPOSE: Generate obfuscated variants of attack samples.

WHY WE NEED THIS:
Real attackers URL-encode payloads, mix case, insert SQL comments.
If we only train on clean textbook attacks, our model will miss
real-world obfuscated versions. Augmentation creates those variants.
"""

import pandas as pd
from urllib.parse import quote
import random
import os


def url_encode_payload(text: str) -> str:
    """URL-encode: <script> -> %3Cscript%3E"""
    return quote(text, safe='=&?/ HTTP/1.Host:')


def mixed_case_payload(text: str) -> str:
    """Randomly mix upper/lowercase: union -> uNiOn"""
    return ''.join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in text
    )


def sql_comment_obfuscate(text: str) -> str:
    """Insert /**/ between SQL keywords: UNION SELECT -> UNION/**/SELECT"""
    keywords = ['union','select','from','where','and','or','insert','drop']
    result = text
    for kw in keywords:
        result = result.replace(kw.upper(), f'{kw.upper()}/**/')
        result = result.replace(kw, f'{kw}/**/')
    return result


def double_encode_payload(text: str) -> str:
    """Double URL-encode: < -> %3C -> %253C"""
    single = quote(text, safe='')
    return single.replace('%', '%25')


def whitespace_obfuscate(text: str) -> str:
    """Add extra spaces: UNION SELECT -> UNION  SELECT"""
    for kw in ['UNION','SELECT','FROM','WHERE','AND','OR','DROP','INSERT']:
        text = text.replace(kw, f'{kw}  ')
    return text


def augment_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create augmented variants of all attack samples.
    Benign samples are NOT augmented (no point making fake benign variants).
    """
    augmented_rows = []

    for _, row in df.iterrows():
        label = row['label']
        text  = row['request_text']

        if label == 'sqli':
            augmented_rows.append({'request_text': sql_comment_obfuscate(text),
                                   'label': label, 'source': 'aug_sql_comment'})
            augmented_rows.append({'request_text': mixed_case_payload(text),
                                   'label': label, 'source': 'aug_mixed_case'})
            augmented_rows.append({'request_text': whitespace_obfuscate(text),
                                   'label': label, 'source': 'aug_whitespace'})

        elif label == 'xss':
            augmented_rows.append({'request_text': url_encode_payload(text),
                                   'label': label, 'source': 'aug_url_encoded'})
            augmented_rows.append({'request_text': mixed_case_payload(text),
                                   'label': label, 'source': 'aug_mixed_case'})

        elif label == 'traversal':
            augmented_rows.append({'request_text': url_encode_payload(text),
                                   'label': label, 'source': 'aug_url_encoded'})
            variant = text.replace('../', '....//').replace('..\\', '....\\\\')
            augmented_rows.append({'request_text': variant,
                                   'label': label, 'source': 'aug_dotdot'})

        elif label == 'cmdi':
            augmented_rows.append({'request_text': url_encode_payload(text),
                                   'label': label, 'source': 'aug_url_encoded'})

    augmented_df = pd.DataFrame(augmented_rows)
    combined = pd.concat([df, augmented_df], ignore_index=True)

    print(f"Original:  {len(df)} samples")
    print(f"Augmented: {len(augmented_df)} new samples added")
    print(f"Total:     {len(combined)} samples")
    print(f"\nLabel distribution:\n{combined['label'].value_counts()}")
    return combined


if __name__ == "__main__":
    data_path = os.path.join(os.path.dirname(__file__), '../../data/custom_payloads.csv')
    df = pd.read_csv(data_path)
    df['request_text'] = df['request_text'].str.strip('"')

    augmented = augment_dataset(df)

    out_path = os.path.join(
        os.path.dirname(__file__), '../../data/processed/augmented_dataset.csv'
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    augmented.to_csv(out_path, index=False)
    print(f"\nSaved to: {out_path}")
