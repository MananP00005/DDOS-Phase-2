#!/usr/bin/env python3
"""
DDoS Defense Phase 2 - Complete Training Pipeline
Extracts features from nginx logs, augments with SMOTE,
trains Random Forest + XGBoost, saves best model
"""

import re, os, json, warnings
import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime
from math import log2
import joblib

from sklearn.model_selection  import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing    import StandardScaler
from sklearn.ensemble         import RandomForestClassifier
from sklearn.metrics          import (classification_report,
                                      confusion_matrix,
                                      accuracy_score, f1_score,
                                      precision_score, recall_score)
from xgboost                  import XGBClassifier
from imblearn.over_sampling   import SMOTE
warnings.filterwarnings('ignore')

# ── Paths ─────────────────────────────────────────────────────────
LAB_LOG   = "/home/<YOUR_USER>/ddos-lab/server/logs/access.log"
MODEL_DIR = "/home/<YOUR_USER>/ddos-lab/defense/models"
DATA_DIR  = "/home/<YOUR_USER>/ddos-lab/defense/data"

FEATURE_COLS = [
    'req_rate',
    'inter_mean',
    'inter_std',
    'unique_urls',
    'url_entropy',
    'pct_heavy',
    'pct_5xx',
    'pct_200',
    'ua_entropy',
    'pct_ab',
    'pct_ddosbot',
    'dur_mean',
    'dur_std',
    'bytes_mean',
]

WINDOW_SEC = 10

# ── Helpers ───────────────────────────────────────────────────────
def entropy(values):
    if not values: return 0.0
    c = defaultdict(int)
    for v in values: c[v] += 1
    t = len(values)
    return -sum((n/t) * log2(n/t) for n in c.values())

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<bytes>\d+) '
    r'"(?P<ua>[^"]*)" (?P<dur>\S+)$'
)

# ══════════════════════════════════════════════════════════════════
# STEP 1 — Parse logs
# ══════════════════════════════════════════════════════════════════
def parse_logs():
    print("\n[1] Parsing nginx access log...")
    records = []
    skipped = 0
    with open(LAB_LOG, errors='ignore') as f:
        for line in f:
            m = LOG_RE.match(line.strip())
            if not m:
                skipped += 1
                continue
            try:
                ts_str = m.group('ts').replace('+00:00','').replace('T',' ')
                ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                records.append({
                    'ip':     m.group('ip'),
                    'ts':     ts,
                    'path':   m.group('path'),
                    'status': int(m.group('status')),
                    'bytes':  int(m.group('bytes')),
                    'ua':     m.group('ua'),
                    'dur':    float(m.group('dur')),
                })
            except:
                skipped += 1
                continue

    print(f"    Parsed  : {len(records):,} records")
    print(f"    Skipped : {skipped:,} malformed lines")
    return records

# ══════════════════════════════════════════════════════════════════
# STEP 2 — Label IPs
# ══════════════════════════════════════════════════════════════════
def label_ips(records):
    print("\n[2] Auto-labelling IPs...")
    by_ip = defaultdict(list)
    for r in records:
        by_ip[r['ip']].append(r)

    attack_ips = set()
    legit_ips  = set()
    skip_ips   = set()

    for ip, reqs in by_ip.items():
        if ip.startswith('172.20'):
            skip_ips.add(ip)
            continue
        uas        = [r['ua'] for r in reqs]
        pct_ab     = sum(1 for u in uas if 'ApacheBench' in u) / len(reqs)
        pct_bot    = sum(1 for u in uas if 'DDoS-Bot'    in u) / len(reqs)
        pct_mozilla= sum(1 for u in uas if 'Mozilla'     in u) / len(reqs)
        paths      = [r['path'] for r in reqs]
        pct_heavy  = sum(1 for p in paths if '/heavy' in p) / len(reqs)

        if (pct_ab + pct_bot) > 0.5:
            attack_ips.add(ip)
        elif pct_mozilla > 0.3:
            legit_ips.add(ip)
        elif len(reqs) > 1000 and pct_heavy > 0.5:
            attack_ips.add(ip)
        else:
            legit_ips.add(ip)

    print(f"    Attack IPs ({len(attack_ips)}): {sorted(attack_ips)}")
    print(f"    Legit  IPs ({len(legit_ips)}): {sorted(list(legit_ips))[:8]}...")
    print(f"    Skipped    ({len(skip_ips)}):  internal/monitoring")
    return by_ip, attack_ips, legit_ips, skip_ips

# ══════════════════════════════════════════════════════════════════
# STEP 3 — Extract features
# ══════════════════════════════════════════════════════════════════
def extract_features(by_ip, attack_ips, legit_ips, skip_ips):
    print("\n[3] Extracting feature vectors...")
    rows = []

    for ip, reqs in by_ip.items():
        if ip in skip_ips:
            continue

        reqs_sorted = sorted(reqs, key=lambda r: r['ts'])
        n_total     = len(reqs_sorted)

        if ip in attack_ips:
            label = 1
        elif ip in legit_ips:
            label = 0
        else:
            continue

        i = 0
        while i < n_total:
            anchor = reqs_sorted[i]['ts']
            window = [r for r in reqs_sorted
                      if 0 <= (r['ts'] - anchor).total_seconds() < WINDOW_SEC]
            if len(window) < 2:
                i += 1
                continue

            n   = len(window)
            rr  = n / WINDOW_SEC

            ts_secs = sorted([(r['ts'] - anchor).total_seconds() for r in window])
            diffs   = [ts_secs[j+1] - ts_secs[j] for j in range(len(ts_secs)-1)]

            paths    = [r['path']   for r in window]
            statuses = [r['status'] for r in window]
            uas      = [r['ua']     for r in window]
            durs     = [r['dur']    for r in window]
            bytes_   = [r['bytes']  for r in window]

            rows.append({
                'ip':          ip,
                'req_rate':    round(rr, 4),
                'inter_mean':  round(np.mean(diffs) if diffs else 0, 4),
                'inter_std':   round(np.std(diffs)  if diffs else 0, 4),
                'unique_urls': len(set(paths)),
                'url_entropy': round(entropy(paths), 4),
                'pct_heavy':   round(sum(1 for p in paths if '/heavy' in p) / n, 4),
                'pct_5xx':     round(sum(1 for s in statuses if s >= 500) / n, 4),
                'pct_200':     round(sum(1 for s in statuses if s == 200) / n, 4),
                'ua_entropy':  round(entropy(uas), 4),
                'pct_ab':      round(sum(1 for u in uas if 'ApacheBench' in u) / n, 4),
                'pct_ddosbot': round(sum(1 for u in uas if 'DDoS-Bot' in u) / n, 4),
                'dur_mean':    round(np.mean(durs), 4),
                'dur_std':     round(np.std(durs), 4),
                'bytes_mean':  round(np.mean(bytes_), 4),
                'label':       label,
            })

            i += max(1, n // 2)

    df = pd.DataFrame(rows)
    a  = df['label'].sum()
    l  = (df['label'] == 0).sum()
    print(f"    Generated : {len(df):,} feature vectors")
    print(f"    Attack    : {a:,}")
    print(f"    Legit     : {l:,}")
    return df

# ══════════════════════════════════════════════════════════════════
# STEP 4 — Balance with SMOTE
# ══════════════════════════════════════════════════════════════════
def balance_dataset(df):
    print("\n[4] Balancing dataset with SMOTE...")
    X = df[FEATURE_COLS].values
    y = df['label'].values

    before_a = y.sum()
    before_l = (y == 0).sum()

    smote = SMOTE(random_state=42, k_neighbors=min(5, before_l - 1))
    X_bal, y_bal = smote.fit_resample(X, y)

    print(f"    Before : Attack={before_a:,}  Legit={before_l:,}")
    print(f"    After  : Attack={y_bal.sum():,}  Legit={(y_bal==0).sum():,}")
    return X_bal, y_bal

# ══════════════════════════════════════════════════════════════════
# STEP 5 — Train and evaluate
# ══════════════════════════════════════════════════════════════════
def train_and_evaluate(X, y):
    print("\n[5] Training models...")

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y)

    print(f"    Train : {len(X_tr):,}   Test : {len(X_te):,}")

    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=15,
            min_samples_leaf=2, n_jobs=-1, random_state=42),
        "XGBoost": XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8, n_jobs=-1,
            random_state=42, eval_metric='logloss', verbosity=0),
    }

    results = {}
    for name, model in models.items():
        print(f"\n    ── {name} ──────────────────────")
        model.fit(X_tr, y_tr)
        y_pred = model.predict(X_te)

        acc  = accuracy_score(y_te, y_pred)
        f1   = f1_score(y_te, y_pred, average='weighted')
        prec = precision_score(y_te, y_pred, average='weighted')
        rec  = recall_score(y_te, y_pred, average='weighted')
        cv   = cross_val_score(model, X_tr, y_tr,
                               cv=StratifiedKFold(5), scoring='f1_weighted')
        cm   = confusion_matrix(y_te, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0

        print(f"    Accuracy  : {acc*100:.2f}%")
        print(f"    F1        : {f1:.4f}")
        print(f"    FPR       : {fpr*100:.2f}%  ← legit wrongly blocked")
        print(f"    CV F1     : {cv.mean():.4f} ± {cv.std():.4f}")
        print(f"\n    Confusion Matrix:")
        print(f"                 Pred Legit  Pred Attack")
        print(f"    Real Legit   {tn:>10,}  {fp:>11,}")
        print(f"    Real Attack  {fn:>10,}  {tp:>11,}")

        results[name] = {
            'model': model, 'scaler': scaler,
            'acc': acc, 'f1': f1, 'prec': prec,
            'rec': rec, 'cv_f1': cv.mean(), 'fpr': fpr,
        }

    best_name = max(results, key=lambda n: results[n]['f1'] - results[n]['fpr'] * 0.3)
    best = results[best_name]

    print(f"\n{'='*55}")
    print(f"  WINNER : {best_name}")
    print(f"  F1     : {best['f1']:.4f}")
    print(f"  Acc    : {best['acc']*100:.2f}%")
    print(f"  FPR    : {best['fpr']*100:.2f}%")
    print(f"{'='*55}")

    return best_name, best, scaler, results

# ══════════════════════════════════════════════════════════════════
# STEP 6 — Feature importance
# ══════════════════════════════════════════════════════════════════
def get_importance(model, name):
    if hasattr(model, 'feature_importances_'):
        imp = model.feature_importances_
    else:
        imp = np.ones(len(FEATURE_COLS)) / len(FEATURE_COLS)

    ranked = sorted(zip(FEATURE_COLS, imp.tolist()),
                    key=lambda x: x[1], reverse=True)
    print(f"\n  Feature Importance ({name}):")
    for feat, val in ranked:
        bar = '█' * int(val * 50)
        print(f"    {feat:<15} {bar} {val:.4f}")
    return dict(ranked)

# ══════════════════════════════════════════════════════════════════
# STEP 7 — Save everything
# ══════════════════════════════════════════════════════════════════
def save_all(model, scaler, name, metrics, feat_imp, all_results, df):
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(DATA_DIR,  exist_ok=True)

    joblib.dump(model,  f"{MODEL_DIR}/best_model.pkl")
    joblib.dump(scaler, f"{MODEL_DIR}/scaler.pkl")

    meta = {
        'model_name':          name,
        'accuracy':            round(metrics['acc'], 4),
        'precision':           round(metrics['prec'], 4),
        'recall':              round(metrics['rec'], 4),
        'f1_score':            round(metrics['f1'], 4),
        'cv_f1':               round(metrics['cv_f1'], 4),
        'false_positive_rate': round(metrics['fpr'], 4),
        'feature_cols':        FEATURE_COLS,
        'feature_importance':  {k: round(v, 4) for k, v in feat_imp.items()},
        'window_sec':          WINDOW_SEC,
        'trained_at':          datetime.now().isoformat(),
        'training_samples':    len(df),
    }
    with open(f"{MODEL_DIR}/model_meta.json", 'w') as f:
        json.dump(meta, f, indent=2)

    comparison = [
        {'model': n, 'accuracy': round(r['acc'], 4),
         'f1': round(r['f1'], 4), 'fpr': round(r['fpr'], 4),
         'cv_f1': round(r['cv_f1'], 4)}
        for n, r in all_results.items()
    ]
    with open(f"{MODEL_DIR}/comparison.json", 'w') as f:
        json.dump(comparison, f, indent=2)

    df.to_csv(f"{DATA_DIR}/features.csv", index=False)

    print(f"\n[7] Saved to {MODEL_DIR}/")
    print(f"    best_model.pkl")
    print(f"    scaler.pkl")
    print(f"    model_meta.json")

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 55)
    print("  DDoS Defense Phase 2 — Training Pipeline")
    print("=" * 55)

    records = parse_logs()
    by_ip, attack_ips, legit_ips, skip_ips = label_ips(records)
    df = extract_features(by_ip, attack_ips, legit_ips, skip_ips)

    os.makedirs(DATA_DIR, exist_ok=True)
    df.to_csv(f"{DATA_DIR}/features_raw.csv", index=False)

    X_bal, y_bal = balance_dataset(df)
    best_name, best, scaler, all_results = train_and_evaluate(X_bal, y_bal)
    feat_imp = get_importance(best['model'], best_name)
    save_all(best['model'], scaler, best_name,
             best, feat_imp, all_results, df)

    print("\n✅ Training complete!")
    print("   Next: run detect.py to start live defense")
