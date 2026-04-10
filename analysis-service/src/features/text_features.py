"""
텍스트 피처 모듈

TF-IDF 벡터화 파이프라인 구축 및 변환.
룰 기반 피처와 결합하여 최종 학습 피처 행렬 생성.
"""

import logging
from pathlib import Path
from typing import Tuple, Optional

import numpy as np
import pandas as pd
import joblib
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

from src.features.rule_features import get_rule_feature_columns

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# TF-IDF 파이프라인
# ─────────────────────────────────────────────

class TextFeatureExtractor:
    """
    TF-IDF + 룰 기반 피처를 결합한 피처 추출기.

    사용법:
        extractor = TextFeatureExtractor()
        X_train = extractor.fit_transform(train_df)
        X_test  = extractor.transform(test_df)
        extractor.save("models/saved/feature_extractor.pkl")
    """

    def __init__(
        self,
        max_features: int = 50000,
        ngram_range: Tuple[int, int] = (1, 2),
        min_df: int = 2,
        max_df: float = 0.95,
        sublinear_tf: bool = True,
        include_rule_features: bool = True,
    ):
        self.tfidf = TfidfVectorizer(
            max_features=max_features,
            ngram_range=ngram_range,
            min_df=min_df,
            max_df=max_df,
            sublinear_tf=sublinear_tf,
            strip_accents="unicode",
            analyzer="word",
            token_pattern=r"\b[a-zA-Z가-힣][a-zA-Z가-힣0-9_-]*\b",
        )
        self.scaler = StandardScaler()
        self.include_rule_features = include_rule_features
        self.rule_feature_cols = get_rule_feature_columns()
        self._is_fitted = False

    def fit_transform(self, df: pd.DataFrame) -> csr_matrix:
        """학습 데이터에 fit + transform"""
        logger.info("Fitting TF-IDF vectorizer...")
        X_tfidf = self.tfidf.fit_transform(df["text_combined"].fillna(""))
        logger.info(f"TF-IDF shape: {X_tfidf.shape}")

        if self.include_rule_features:
            X_rule = self._get_rule_matrix(df, fit=True)
            X = hstack([X_tfidf, X_rule])
            logger.info(f"Combined feature shape: {X.shape}")
        else:
            X = X_tfidf

        self._is_fitted = True
        return X

    def transform(self, df: pd.DataFrame) -> csr_matrix:
        """학습된 vectorizer로 새 데이터 변환"""
        if not self._is_fitted:
            raise RuntimeError("Call fit_transform() before transform()")

        X_tfidf = self.tfidf.transform(df["text_combined"].fillna(""))

        if self.include_rule_features:
            X_rule = self._get_rule_matrix(df, fit=False)
            X = hstack([X_tfidf, X_rule])
        else:
            X = X_tfidf

        return X

    def _get_rule_matrix(self, df: pd.DataFrame, fit: bool) -> csr_matrix:
        """룰 기반 피처 컬럼을 StandardScaler 적용 후 sparse matrix로 변환"""
        available_cols = [c for c in self.rule_feature_cols if c in df.columns]
        if not available_cols:
            logger.warning("No rule feature columns found in DataFrame.")
            return csr_matrix((len(df), 0))

        X_rule_raw = df[available_cols].fillna(0).values.astype(float)
        if fit:
            X_rule_scaled = self.scaler.fit_transform(X_rule_raw)
        else:
            X_rule_scaled = self.scaler.transform(X_rule_raw)

        return csr_matrix(X_rule_scaled)

    def get_tfidf_feature_names(self) -> list:
        """TF-IDF 피처명 반환 (SHAP 설명용)"""
        return list(self.tfidf.get_feature_names_out())

    def get_all_feature_names(self) -> list:
        """TF-IDF + 룰 피처 전체 이름 반환"""
        tfidf_names = self.get_tfidf_feature_names()
        if self.include_rule_features:
            rule_names = [c for c in self.rule_feature_cols]
            return tfidf_names + rule_names
        return tfidf_names

    def save(self, path: str) -> None:
        joblib.dump(self, path)
        logger.info(f"Feature extractor saved: {path}")

    @classmethod
    def load(cls, path: str) -> "TextFeatureExtractor":
        extractor = joblib.load(path)
        logger.info(f"Feature extractor loaded: {path}")
        return extractor


# ─────────────────────────────────────────────
# 편의 함수
# ─────────────────────────────────────────────

def prepare_features(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    config: Optional[dict] = None,
) -> Tuple[csr_matrix, csr_matrix, csr_matrix, TextFeatureExtractor]:
    """
    train/val/test 피처 행렬과 학습된 extractor를 반환.

    Returns:
        X_train, X_val, X_test, extractor
    """
    tfidf_config = config.get("tfidf", {}) if config else {}

    extractor = TextFeatureExtractor(
        max_features=tfidf_config.get("max_features", 50000),
        ngram_range=tuple(tfidf_config.get("ngram_range", [1, 2])),
        min_df=tfidf_config.get("min_df", 2),
        max_df=tfidf_config.get("max_df", 0.95),
        sublinear_tf=tfidf_config.get("sublinear_tf", True),
    )

    X_train = extractor.fit_transform(train_df)
    X_val   = extractor.transform(val_df)
    X_test  = extractor.transform(test_df)

    return X_train, X_val, X_test, extractor
