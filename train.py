"""
train.py — DNS Shield
Loads dns_training_data.csv, trains an Isolation Forest, evaluates it,
and serialises the fitted model to dns_model.pkl.

Usage:
    python train.py
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

DATA_PATH  = "dns_training_data.csv"
MODEL_PATH = "dns_model.pkl"

# Contamination = expected fraction of anomalies in the training set.
# With 500 malicious / 2500 total ≈ 0.20.  Adjust if you regenerate data.
CONTAMINATION = 0.20

# Isolation Forest hyper-parameters
N_ESTIMATORS   = 200   # more trees → more stable scoring
MAX_SAMPLES    = "auto"
RANDOM_STATE   = 42

# Hold-out split for evaluation (stratified so both classes are represented)
TEST_SIZE      = 0.15


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def load_data(path: str) -> pd.DataFrame:
    """Load and validate the training CSV."""
    if not os.path.exists(path):
        print(f"[ERROR] Training data not found: {path}")
        print("        Run  python data_generator.py  first.")
        sys.exit(1)

    df = pd.read_csv(path)
    required = {"length", "entropy", "label"}
    if not required.issubset(df.columns):
        print(f"[ERROR] CSV missing required columns. Found: {list(df.columns)}")
        sys.exit(1)

    print(f"[*] Loaded {len(df):,} rows from '{path}'")
    print(f"    Benign  (0): {(df['label'] == 0).sum():,}")
    print(f"    Anomaly (1): {(df['label'] == 1).sum():,}")
    return df


def build_feature_matrix(df: pd.DataFrame) -> tuple:
    """Return X (features) and y (labels) arrays."""
    X = df[["length", "entropy"]].values.astype(float)
    y = df["label"].values.astype(int)
    return X, y


def train_model(X_train: np.ndarray) -> IsolationForest:
    """
    Fit an Isolation Forest on the training features.
    NOTE: IsolationForest is unsupervised — labels are NOT used during fit.
    The model learns the 'normal' data distribution and flags deviations.
    """
    print(f"\n[*] Training IsolationForest  (n_estimators={N_ESTIMATORS}, "
          f"contamination={CONTAMINATION}) …")

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        max_samples=MAX_SAMPLES,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,          # use all CPU cores
        warm_start=False,
    )
    model.fit(X_train)
    print("[✓] Training complete.")
    return model


def evaluate_model(model: IsolationForest, X_test: np.ndarray, y_test: np.ndarray) -> None:
    """
    Run the model on the hold-out split and print a full diagnostic report.
    IsolationForest predicts:
        +1  → inlier  (normal / benign)
        -1  → outlier (anomaly / malicious)
    We remap to 0/1 to match our label convention.
    """
    print("\n[*] Evaluating on hold-out split …")
    raw_preds = model.predict(X_test)

    # Remap: +1 -> 0 (benign), -1 -> 1 (anomaly)
    y_pred = np.where(raw_preds == 1, 0, 1)

    target_names = ["Benign (0)", "Anomaly (1)"]
    print("\n── Classification Report ─────────────────────────────────────────")
    print(classification_report(y_test, y_pred, target_names=target_names))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print("── Confusion Matrix ──────────────────────────────────────────────")
    print(f"  True  Negatives (benign correctly passed)  : {tn:>5}")
    print(f"  False Positives (benign flagged as malicious): {fp:>4}")
    print(f"  False Negatives (malicious missed)          : {fn:>4}")
    print(f"  True  Positives (malicious correctly blocked): {tp:>4}")
    print(f"\n  Detection Rate   : {tp / (tp + fn) * 100:.1f}%")
    print(f"  False Alarm Rate : {fp / (fp + tn) * 100:.1f}%")
    print("──────────────────────────────────────────────────────────────────")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    # 1. Load data
    df = load_data(DATA_PATH)

    # 2. Build feature matrix
    X, y = build_feature_matrix(df)

    # 3. Stratified train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    print(f"\n[*] Split → train: {len(X_train):,}   test: {len(X_test):,} (stratified)")

    # 4. Train (unsupervised — only X_train, no labels)
    model = train_model(X_train)

    # 5. Evaluate
    evaluate_model(model, X_test, y_test)

    # 6. Serialise model
    joblib.dump(model, MODEL_PATH)
    model_size_kb = os.path.getsize(MODEL_PATH) / 1024
    print(f"\n[✓] Model saved → {MODEL_PATH}  ({model_size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
