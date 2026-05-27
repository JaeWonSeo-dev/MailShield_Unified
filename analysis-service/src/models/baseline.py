"""
베이스라인 모델 모듈

포함 모델:
  - Logistic Regression (TF-IDF 기반 해석 용이)
  - Random Forest (Feature Importance + SHAP 적용 용이)
  - Linear SVM (텍스트 분류 강자)
  - XGBoost (권장 MVP 모델)

개선 사항:
  - 평가 지표/리포트를 파일로 저장
  - threshold를 config에서 일관되게 사용
  - 학습 산출물 추적성을 높이기 위한 reports 디렉터리 추가
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
from scipy.sparse import csr_matrix
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegressionCV
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.svm import LinearSVC

try:
    from xgboost import XGBClassifier
except Exception as exc:
    XGBClassifier = None
    XGBOOST_IMPORT_ERROR = exc
else:
    XGBOOST_IMPORT_ERROR = None

logger = logging.getLogger(__name__)

CLASS_NAMES = ["ham", "spam", "phishing"]
CLASS_LABELS = {name: idx for idx, name in enumerate(CLASS_NAMES)}
PHISHING_ALIASES = {"phishing", "fraud", "scam", "malware"}


def build_multiclass_target(df) -> np.ndarray:
    """Map dataset label_type values into normal/spam/phishing classes."""
    if "label_type" not in df.columns:
        return df["label"].values

    def map_label(value: Any) -> int:
        label_type = str(value or "").strip().lower()
        if label_type == "spam":
            return CLASS_LABELS["spam"]
        if label_type in PHISHING_ALIASES:
            return CLASS_LABELS["phishing"]
        return CLASS_LABELS["ham"]

    return df["label_type"].map(map_label).astype(int).values


def class_balance_summary(y: np.ndarray) -> Dict[str, int]:
    return {name: int((y == idx).sum()) for name, idx in CLASS_LABELS.items()}


def predict_scores(model, X: csr_matrix) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    if hasattr(model, "decision_function"):
        raw = model.decision_function(X)
        return 1 / (1 + np.exp(-raw))
    return model.predict(X).astype(float)


def find_best_threshold(
    model,
    X: csr_matrix,
    y: np.ndarray,
    metric: str = "f1",
    min_threshold: float = 0.1,
    max_threshold: float = 0.9,
    step: float = 0.01,
) -> Dict[str, float]:
    target_metric = metric if metric in {"precision", "recall", "f1"} else "f1"
    scores = predict_scores(model, X)
    best = {"threshold": 0.5, target_metric: -1.0, "precision": 0.0, "recall": 0.0, "f1": 0.0}

    for threshold in np.arange(min_threshold, max_threshold + step, step):
        y_pred = (scores >= threshold).astype(int)
        values = {
            "precision": precision_score(y, y_pred, zero_division=0),
            "recall": recall_score(y, y_pred, zero_division=0),
            "f1": f1_score(y, y_pred, zero_division=0),
        }
        target_value = values[target_metric]
        if target_value > best[target_metric]:
            best = {
                "threshold": round(float(threshold), 2),
                "precision": round(float(values["precision"]), 4),
                "recall": round(float(values["recall"]), 4),
                "f1": round(float(values["f1"]), 4),
                target_metric: round(float(target_value), 4),
            }

    return best


def evaluate_model(
    model,
    X: csr_matrix,
    y: np.ndarray,
    threshold: float = 0.5,
    model_name: str = "Model",
    class_names: list[str] | None = None,
) -> Dict[str, Any]:
    """모델 평가 후 지표 딕셔너리 반환."""
    class_names = class_names or ["ham", "threat"]
    labels = list(range(len(class_names)))

    if len(class_names) > 2:
        if hasattr(model, "predict_proba"):
            y_pred_proba = model.predict_proba(X)
            y_pred = labels and np.asarray(getattr(model, "classes_", labels))[np.argmax(y_pred_proba, axis=1)]
        else:
            y_pred_proba = None
            y_pred = model.predict(X)
    else:
        y_pred_proba = predict_scores(model, X)
        y_pred = (y_pred_proba >= threshold).astype(int)

    report_text = classification_report(y, y_pred, labels=labels, target_names=class_names, zero_division=0)
    conf = confusion_matrix(y, y_pred, labels=labels)
    metrics = {
        "threshold": threshold,
        "accuracy": round(accuracy_score(y, y_pred), 4),
        "f1_macro": round(f1_score(y, y_pred, average="macro", zero_division=0), 4),
        "f1_weighted": round(f1_score(y, y_pred, average="weighted", zero_division=0), 4),
        "precision_macro": round(precision_score(y, y_pred, average="macro", zero_division=0), 4),
        "recall_macro": round(recall_score(y, y_pred, average="macro", zero_division=0), 4),
        "conf_matrix": conf.tolist(),
        "classification_report": report_text,
    }
    if len(class_names) == 2:
        tn, fp, fn, tp = conf.ravel()
        metrics.update({
            "f1": round(f1_score(y, y_pred, zero_division=0), 4),
            "precision": round(precision_score(y, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y, y_pred, zero_division=0), 4),
            "tp": int(tp),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "roc_auc": round(roc_auc_score(y, y_pred_proba), 4),
        })
    elif y_pred_proba is not None:
        metrics["roc_auc_ovr"] = round(roc_auc_score(y, y_pred_proba, multi_class="ovr", average="macro"), 4)
        for idx, name in enumerate(class_names):
            metrics[f"{name}_f1"] = round(f1_score(y == idx, y_pred == idx, zero_division=0), 4)
            metrics[f"{name}_precision"] = round(precision_score(y == idx, y_pred == idx, zero_division=0), 4)
            metrics[f"{name}_recall"] = round(recall_score(y == idx, y_pred == idx, zero_division=0), 4)

    logger.info(
        f"[{model_name}] F1_macro={metrics['f1_macro']} | Accuracy={metrics['accuracy']} | "
        f"AUC={metrics.get('roc_auc_ovr', metrics.get('roc_auc', 'N/A'))} | threshold={threshold}"
    )
    print(f"\n=== {model_name} Classification Report ===")
    print(report_text)
    return metrics


def save_metrics(metrics: Dict[str, Any], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)
    logger.info(f"Metrics saved: {path}")


def evaluate_by_column(model, X: csr_matrix, df, column: str, threshold: float = 0.5, class_names: list[str] | None = None) -> list:
    if column not in df.columns:
        return []
    class_names = class_names or ["ham", "threat"]
    labels = list(range(len(class_names)))
    if len(class_names) > 2:
        scores = model.predict_proba(X) if hasattr(model, "predict_proba") else None
        pred = np.asarray(getattr(model, "classes_", labels))[np.argmax(scores, axis=1)] if scores is not None else model.predict(X)
    else:
        scores = predict_scores(model, X)
        pred = (scores >= threshold).astype(int)
    rows = []
    target_column = "target" if "target" in df.columns else "label"
    eval_df = df[[column, target_column]].copy()
    eval_df["_pred"] = pred
    for value, group in eval_df.groupby(column):
        y = group[target_column].values
        p = group["_pred"].values
        row = {
            column: str(value),
            "n": int(len(group)),
            "accuracy": round(accuracy_score(y, p), 4),
            "f1_macro": round(f1_score(y, p, average="macro", zero_division=0), 4),
            "precision_macro": round(precision_score(y, p, average="macro", zero_division=0), 4),
            "recall_macro": round(recall_score(y, p, average="macro", zero_division=0), 4),
        }
        rows.append(row)
    return sorted(rows, key=lambda item: item["n"], reverse=True)


def save_results_bundle(summary: Dict[str, Any], results_dir: Path) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    latest_json = results_dir / "latest-summary.json"
    latest_md = results_dir / "latest-summary.md"
    archived_json = results_dir / f"training-summary-{timestamp}.json"
    archived_md = results_dir / f"training-summary-{timestamp}.md"

    markdown_lines = [
        "# Training Results",
        "",
        f"- generated_at: {summary.get('generated_at', '')}",
        f"- classification_mode: {summary.get('classification_mode', 'binary')}",
        f"- primary_metric: {summary.get('primary_metric', '')}",
        f"- class_balance: {summary.get('class_balance', {})}",
        "",
    ]

    for model_name, splits in summary.get("models", {}).items():
        markdown_lines.append(f"## {model_name}")
        markdown_lines.append("")
        for split_name, metrics in splits.items():
            markdown_lines.extend([
                f"### {split_name}",
                "",
                f"- accuracy: {metrics.get('accuracy', '')}",
                f"- f1_macro: {metrics.get('f1_macro', metrics.get('f1', ''))}",
                f"- precision_macro: {metrics.get('precision_macro', metrics.get('precision', ''))}",
                f"- recall_macro: {metrics.get('recall_macro', metrics.get('recall', ''))}",
                f"- roc_auc: {metrics.get('roc_auc_ovr', metrics.get('roc_auc', 'N/A'))}",
                f"- ham_f1: {metrics.get('ham_f1', '')}",
                f"- spam_f1: {metrics.get('spam_f1', '')}",
                f"- phishing_f1: {metrics.get('phishing_f1', '')}",
                "",
            ])

    for target in (latest_json, archived_json):
        with open(target, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        logger.info(f"Results summary saved: {target}")

    markdown = "\n".join(markdown_lines)
    for target in (latest_md, archived_md):
        with open(target, "w", encoding="utf-8") as f:
            f.write(markdown)
        logger.info(f"Results summary saved: {target}")


def save_model_metadata(metadata: Dict[str, Any], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)
    logger.info(f"Model metadata saved: {path}")


def train_logistic_regression(X_train, y_train, Cs=5, cv: int = 5, max_iter: int = 1000, random_state: int = 42):
    logger.info(f"Training LogisticRegressionCV (cv={cv}, Cs={Cs})...")
    model = LogisticRegressionCV(
        Cs=Cs,
        cv=cv,
        max_iter=max_iter,
        random_state=random_state,
        class_weight="balanced",
        solver="saga",
        scoring="f1_macro" if len(set(y_train)) > 2 else "f1",
        n_jobs=-1,
        refit=True,
    )
    model.fit(X_train, y_train)
    logger.info(f"Best C selected by CV: {model.C_[0]:.6f}")
    return model


def train_random_forest(X_train, y_train, n_estimators: int = 200, max_depth: int = 20, random_state: int = 42):
    logger.info("Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_split=5,
        random_state=random_state,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model


def train_svm(X_train, y_train, C: float = 1.0, random_state: int = 42):
    logger.info("Training Linear SVM (with calibration)...")
    base_svm = LinearSVC(C=C, max_iter=2000, random_state=random_state, class_weight="balanced")
    model = CalibratedClassifierCV(base_svm, cv=3)
    model.fit(X_train, y_train)
    return model


def train_xgboost(
    X_train,
    y_train,
    X_val=None,
    y_val=None,
    n_estimators: int = 500,
    max_depth: int = 4,
    learning_rate: float = 0.05,
    subsample: float = 0.8,
    colsample_bytree: float = 0.8,
    early_stopping_rounds: int = 20,
    random_state: int = 42,
    scale_pos_weight: float = 1.0,
    device: str = "cpu",
    tree_method: str = "hist",
):
    logger.info(
        f"Training XGBoost (max {n_estimators} rounds, early_stopping={early_stopping_rounds}, "
        f"device={device}, tree_method={tree_method})..."
    )

    if XGBClassifier is None:
        raise RuntimeError(f"XGBoost is unavailable: {XGBOOST_IMPORT_ERROR}")

    if X_val is None or y_val is None:
        raise ValueError("XGBoost early stopping requires X_val and y_val")

    model = XGBClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        subsample=subsample,
        colsample_bytree=colsample_bytree,
        random_state=random_state,
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        tree_method=tree_method,
        device=device,
        early_stopping_rounds=early_stopping_rounds,
        n_jobs=-1,
    )
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=50)
    logger.info(f"XGBoost stopped at round {model.best_iteration} / {n_estimators}")
    return model


def save_model(model, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    logger.info(f"Model saved: {path}")


def load_model(path: str):
    model = joblib.load(path)
    logger.info(f"Model loaded: {path}")
    return model


def compare_models(X_train, y_train, X_val, y_val, random_state: int = 42, threshold: float = 0.5) -> Dict[str, Dict]:
    results = {}
    models_to_train = {
        "Logistic Regression": lambda: train_logistic_regression(X_train, y_train, random_state=random_state),
        "Random Forest": lambda: train_random_forest(X_train, y_train, random_state=random_state),
        "Linear SVM": lambda: train_svm(X_train, y_train, random_state=random_state),
        "XGBoost": lambda: train_xgboost(X_train, y_train, X_val, y_val, random_state=random_state),
    }

    for name, train_fn in models_to_train.items():
        try:
            model = train_fn()
            metrics = evaluate_model(model, X_val, y_val, threshold=threshold, model_name=name)
            results[name] = {"model": model, "metrics": metrics}
        except Exception as e:
            logger.error(f"Model {name} failed: {e}")
            results[name] = {"model": None, "metrics": {}, "error": str(e)}
    return results


if __name__ == "__main__":
    import pandas as pd
    import sys
    import yaml

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    sys.path.insert(0, str(Path(__file__).parents[2]))

    from src.data.augmentation import augment_training_data
    from src.features.rule_features import add_rule_features
    from src.features.model_text import build_model_text_dataframe
    from src.features.text_features import prepare_features

    root = Path(__file__).parents[2]
    with open(root / "config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    processed_dir = root / config["paths"]["processed_data_dir"]
    models_dir = root / config["paths"]["models_dir"]
    reports_dir = root / config["paths"].get("reports_dir", "reports")
    results_dir = root / "results"
    default_threshold = float(config.get("evaluation", {}).get("threshold", 0.5))
    primary_metric = str(config.get("evaluation", {}).get("primary_metric", "f1"))

    logger.info("Loading processed data...")
    train_df = pd.read_csv(processed_dir / "train.csv")
    val_df = pd.read_csv(processed_dir / "val.csv")
    test_df = pd.read_csv(processed_dir / "test.csv")

    aug_cfg = config.get("augmentation", {})
    before_aug = len(train_df)
    train_df = augment_training_data(train_df, aug_cfg)
    logger.info(f"Training rows: {before_aug} -> {len(train_df)} (augmentation)")

    logger.info("Building model text from mail fields...")
    train_df["text_combined"] = build_model_text_dataframe(train_df)
    val_df["text_combined"] = build_model_text_dataframe(val_df)
    test_df["text_combined"] = build_model_text_dataframe(test_df)
    train_df["target"] = build_multiclass_target(train_df)
    val_df["target"] = build_multiclass_target(val_df)
    test_df["target"] = build_multiclass_target(test_df)

    include_rule_features = bool(config.get("model_features", {}).get("include_rule_features", False))
    if include_rule_features:
        logger.info("Adding rule features as model inputs...")
        train_df = add_rule_features(train_df)
        val_df = add_rule_features(val_df)
        test_df = add_rule_features(test_df)
    else:
        logger.info("Training text-only model inputs; rule features are excluded from prediction.")

    logger.info("Building feature matrices...")
    X_train, X_val, X_test, extractor = prepare_features(train_df, val_df, test_df, config)
    y_train = train_df["target"].values
    y_val = val_df["target"].values
    y_test = test_df["target"].values

    balance = class_balance_summary(y_train)
    logger.info(f"Class balance (train): {balance}")

    lr_cfg = config.get("models", {}).get("logistic_regression", {})
    lr_model = train_logistic_regression(
        X_train,
        y_train,
        Cs=lr_cfg.get("Cs", 5),
        cv=int(lr_cfg.get("cv", config.get("evaluation", {}).get("cv_folds", 5))),
        max_iter=int(lr_cfg.get("max_iter", 1000)),
        random_state=config["data"]["random_seed"],
    )
    lr_threshold = default_threshold
    logger.info("LogisticRegressionCV uses argmax over ham/spam/phishing probabilities.")
    lr_val_metrics = evaluate_model(lr_model, X_val, y_val, threshold=lr_threshold, model_name="LogisticRegressionCV [val]", class_names=CLASS_NAMES)
    lr_test_metrics = evaluate_model(lr_model, X_test, y_test, threshold=lr_threshold, model_name="LogisticRegressionCV [test]", class_names=CLASS_NAMES)
    lr_val_by_source = evaluate_by_column(lr_model, X_val, val_df, "source", threshold=lr_threshold, class_names=CLASS_NAMES)
    lr_test_by_source = evaluate_by_column(lr_model, X_test, test_df, "source", threshold=lr_threshold, class_names=CLASS_NAMES)
    save_model(lr_model, str(models_dir / "lr_model.pkl"))
    save_metrics(lr_val_metrics, str(reports_dir / "lr_val_metrics.json"))
    save_metrics(lr_test_metrics, str(reports_dir / "lr_test_metrics.json"))
    save_metrics({"source_metrics": lr_test_by_source}, str(reports_dir / "lr_test_by_source.json"))

    xgb_cfg = config.get("models", {}).get("xgboost", {})
    xgb_model = None
    xgb_val_metrics = {}
    xgb_test_metrics = {}
    xgb_threshold = default_threshold
    try:
        raise RuntimeError("XGBoost training is skipped for the 3-class production target; LogisticRegressionCV is the active calibrated model.")
        xgb_model = train_xgboost(
            X_train,
            y_train,
            X_val,
            y_val,
            n_estimators=int(xgb_cfg.get("n_estimators", 500)),
            max_depth=int(xgb_cfg.get("max_depth", 4)),
            learning_rate=float(xgb_cfg.get("learning_rate", 0.05)),
            subsample=float(xgb_cfg.get("subsample", 0.8)),
            colsample_bytree=float(xgb_cfg.get("colsample_bytree", 0.8)),
            early_stopping_rounds=20,
            random_state=config["data"]["random_seed"],
            scale_pos_weight=1.0,
            device=str(xgb_cfg.get("device", "cpu")),
            tree_method=str(xgb_cfg.get("tree_method", "hist")),
        )
        xgb_threshold = default_threshold
        logger.info(f"XGBoost best validation threshold={xgb_threshold}")
        xgb_val_metrics = evaluate_model(xgb_model, X_val, y_val, threshold=xgb_threshold, model_name="XGBoost [val]", class_names=CLASS_NAMES)
        xgb_test_metrics = evaluate_model(xgb_model, X_test, y_test, threshold=xgb_threshold, model_name="XGBoost [test]", class_names=CLASS_NAMES)
        save_model(xgb_model, str(models_dir / "xgboost_model.pkl"))
        save_metrics(xgb_val_metrics, str(reports_dir / "xgb_val_metrics.json"))
        save_metrics(xgb_test_metrics, str(reports_dir / "xgb_test_metrics.json"))
    except Exception as exc:
        logger.warning(f"XGBoost training skipped/failed: {exc}")

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "default_threshold": default_threshold,
        "primary_metric": primary_metric,
        "model_features": {
            "include_rule_features": include_rule_features,
            "text_fields": ["subject", "body", "sender", "sender_domain", "reply_to", "reply_to_domain", "urls", "attachments"],
        },
        "classification_mode": "multiclass",
        "class_names": CLASS_NAMES,
        "class_balance": balance,
        "models": {
            "logistic_regression": {"val": lr_val_metrics, "test": lr_test_metrics},
            "xgboost": {"val": xgb_val_metrics, "test": xgb_test_metrics},
        },
    }
    save_metrics(summary, str(reports_dir / "training_summary.json"))
    save_results_bundle(summary, results_dir)

    extractor.save(str(models_dir / "feature_extractor.pkl"))
    metadata = {
        "generated_at": summary["generated_at"],
        "primary_metric": primary_metric,
        "default_threshold": default_threshold,
        "classification_mode": "multiclass",
        "class_names": CLASS_NAMES,
        "class_labels": CLASS_LABELS,
        "phishing_severity_thresholds": {"low": 0.4, "medium": 0.65, "high": 0.85},
        "models": {
            "lr": {"threshold": lr_threshold, "val": lr_val_metrics, "test": lr_test_metrics},
            "logistic_regression": {"threshold": lr_threshold, "val": lr_val_metrics, "test": lr_test_metrics},
            "xgboost": {"threshold": xgb_threshold, "val": xgb_val_metrics, "test": xgb_test_metrics},
        },
        "diagnostics": {
            "val_by_source": lr_val_by_source,
            "test_by_source": lr_test_by_source,
        },
        "model_features": summary["model_features"],
    }
    save_model_metadata(metadata, str(models_dir / "model_metadata.json"))
    print("\n모델 학습 완료!")
