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
from xgboost import XGBClassifier

logger = logging.getLogger(__name__)


def evaluate_model(
    model,
    X: csr_matrix,
    y: np.ndarray,
    threshold: float = 0.5,
    model_name: str = "Model",
) -> Dict[str, Any]:
    """모델 평가 후 지표 딕셔너리 반환."""
    y_pred_proba = None
    if hasattr(model, "predict_proba"):
        y_pred_proba = model.predict_proba(X)[:, 1]
        y_pred = (y_pred_proba >= threshold).astype(int)
    else:
        y_pred = model.predict(X)

    report_text = classification_report(y, y_pred, target_names=["ham", "threat"], zero_division=0)
    metrics = {
        "threshold": threshold,
        "accuracy": round(accuracy_score(y, y_pred), 4),
        "f1": round(f1_score(y, y_pred, zero_division=0), 4),
        "precision": round(precision_score(y, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y, y_pred, zero_division=0), 4),
        "conf_matrix": confusion_matrix(y, y_pred).tolist(),
        "classification_report": report_text,
    }
    if y_pred_proba is not None:
        metrics["roc_auc"] = round(roc_auc_score(y, y_pred_proba), 4)

    logger.info(
        f"[{model_name}] F1={metrics['f1']} | Precision={metrics['precision']} | "
        f"Recall={metrics['recall']} | AUC={metrics.get('roc_auc', 'N/A')} | threshold={threshold}"
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


def train_logistic_regression(X_train, y_train, Cs: int = 5, cv: int = 5, max_iter: int = 1000, random_state: int = 42):
    logger.info(f"Training LogisticRegressionCV (cv={cv}, Cs={Cs})...")
    model = LogisticRegressionCV(
        Cs=Cs,
        cv=cv,
        max_iter=max_iter,
        random_state=random_state,
        class_weight="balanced",
        solver="saga",
        scoring="f1",
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
):
    logger.info(f"Training XGBoost (max {n_estimators} rounds, early_stopping={early_stopping_rounds})...")

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
        tree_method="hist",
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
    from src.features.text_features import prepare_features

    root = Path(__file__).parents[2]
    with open(root / "config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    processed_dir = root / config["paths"]["processed_data_dir"]
    models_dir = root / config["paths"]["models_dir"]
    reports_dir = root / config["paths"].get("reports_dir", "reports")
    threshold = float(config.get("evaluation", {}).get("threshold", 0.5))

    logger.info("Loading processed data...")
    train_df = pd.read_csv(processed_dir / "train.csv")
    val_df = pd.read_csv(processed_dir / "val.csv")
    test_df = pd.read_csv(processed_dir / "test.csv")

    aug_cfg = config.get("augmentation", {})
    before_aug = len(train_df)
    train_df = augment_training_data(train_df, aug_cfg)
    logger.info(f"Training rows: {before_aug} -> {len(train_df)} (augmentation)")

    logger.info("Adding rule features...")
    train_df = add_rule_features(train_df)
    val_df = add_rule_features(val_df)
    test_df = add_rule_features(test_df)

    logger.info("Building feature matrices...")
    X_train, X_val, X_test, extractor = prepare_features(train_df, val_df, test_df, config)
    y_train = train_df["label"].values
    y_val = val_df["label"].values
    y_test = test_df["label"].values

    pos_count = max(1, int((y_train == 1).sum()))
    neg_count = max(1, int((y_train == 0).sum()))
    auto_scale_pos_weight = round(neg_count / pos_count, 4)
    logger.info(f"Class balance (train): neg={neg_count}, pos={pos_count}, auto_scale_pos_weight={auto_scale_pos_weight}")

    lr_model = train_logistic_regression(X_train, y_train, Cs=5, cv=5, random_state=config["data"]["random_seed"])
    lr_val_metrics = evaluate_model(lr_model, X_val, y_val, threshold=threshold, model_name="LogisticRegressionCV [val]")
    lr_test_metrics = evaluate_model(lr_model, X_test, y_test, threshold=threshold, model_name="LogisticRegressionCV [test]")
    save_model(lr_model, str(models_dir / "lr_model.pkl"))
    save_metrics(lr_val_metrics, str(reports_dir / "lr_val_metrics.json"))
    save_metrics(lr_test_metrics, str(reports_dir / "lr_test_metrics.json"))

    xgb_model = train_xgboost(
        X_train,
        y_train,
        X_val,
        y_val,
        n_estimators=500,
        max_depth=4,
        learning_rate=0.05,
        early_stopping_rounds=20,
        random_state=config["data"]["random_seed"],
        scale_pos_weight=auto_scale_pos_weight,
    )
    xgb_val_metrics = evaluate_model(xgb_model, X_val, y_val, threshold=threshold, model_name="XGBoost [val]")
    xgb_test_metrics = evaluate_model(xgb_model, X_test, y_test, threshold=threshold, model_name="XGBoost [test]")
    save_model(xgb_model, str(models_dir / "xgboost_model.pkl"))
    save_metrics(xgb_val_metrics, str(reports_dir / "xgb_val_metrics.json"))
    save_metrics(xgb_test_metrics, str(reports_dir / "xgb_test_metrics.json"))

    summary = {
        "threshold": threshold,
        "class_balance": {"neg": neg_count, "pos": pos_count, "scale_pos_weight": auto_scale_pos_weight},
        "models": {
            "logistic_regression": {"val": lr_val_metrics, "test": lr_test_metrics},
            "xgboost": {"val": xgb_val_metrics, "test": xgb_test_metrics},
        },
    }
    save_metrics(summary, str(reports_dir / "training_summary.json"))

    extractor.save(str(models_dir / "feature_extractor.pkl"))
    print("\n모델 학습 완료!")
