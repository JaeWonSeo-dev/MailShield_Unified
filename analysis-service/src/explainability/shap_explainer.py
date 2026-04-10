"""
SHAP 기반 설명 모듈

XGBoost / Random Forest 모델에 SHAP TreeExplainer 적용.
상위 기여 피처(단어, 룰)를 추출하고 시각화하는 기능 제공.
"""

import logging
from typing import List, Tuple, Optional, Dict, Any

import numpy as np

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# SHAP 기반 피처 중요도 추출
# ─────────────────────────────────────────────

class ShapExplainer:
    """
    TreeExplainer 기반 SHAP 설명기.
    XGBoost, Random Forest 모델과 함께 사용.

    사용법:
        explainer = ShapExplainer(model, feature_names)
        top_features = explainer.get_top_features(X_single)
        explainer.plot_waterfall(X_single)  # 노트북에서 사용
    """

    def __init__(self, model, feature_names: List[str]):
        """
        Args:
            model: 학습된 XGBoost 또는 RandomForest 모델
            feature_names: 전체 피처 이름 목록 (TF-IDF + 룰 피처 포함)
        """
        try:
            import shap
            self.shap = shap
        except ImportError:
            raise ImportError("shap 패키지가 필요합니다: pip install shap")

        self.model = model
        self.feature_names = feature_names
        self._explainer = None
        self._init_explainer()

    def _init_explainer(self):
        try:
            self._explainer = self.shap.TreeExplainer(self.model)
            logger.info("SHAP TreeExplainer initialized.")
        except Exception as e:
            logger.warning(f"TreeExplainer init failed, falling back to Explainer: {e}")
            self._explainer = self.shap.Explainer(self.model)

    def get_shap_values(self, X) -> np.ndarray:
        """
        입력 X에 대한 SHAP 값 반환.
        binary classification의 경우 클래스 1(위협)의 SHAP 값 반환.
        """
        shap_values = self._explainer.shap_values(X)

        # RandomForest는 [class0_shap, class1_shap] 형태 반환
        if isinstance(shap_values, list) and len(shap_values) == 2:
            return shap_values[1]  # 클래스 1 (위협)
        return shap_values

    def get_top_features(
        self,
        X_single,
        top_n: int = 10,
    ) -> List[Tuple[str, float]]:
        """
        단일 샘플에 대한 상위 기여 피처 반환.

        Returns:
            [(feature_name, shap_value), ...] 기여도 절대값 내림차순
        """
        shap_vals = self.get_shap_values(X_single)

        if shap_vals.ndim == 2:
            shap_vals = shap_vals[0]

        # 피처명과 SHAP 값 매핑
        if len(self.feature_names) == len(shap_vals):
            pairs = list(zip(self.feature_names, shap_vals))
        else:
            pairs = [(f"feature_{i}", v) for i, v in enumerate(shap_vals)]

        # 절대값 기준 내림차순 정렬
        pairs.sort(key=lambda x: abs(x[1]), reverse=True)
        return pairs[:top_n]

    def shap_features_to_explanation(
        self,
        top_features: List[Tuple[str, float]],
        threshold: float = 0.01,
    ) -> Dict[str, Any]:
        """
        상위 SHAP 피처를 설명 가능한 카테고리로 분류.

        Returns:
            {
              "positive_words": [...],   # 피싱 판정에 기여한 단어/피처
              "negative_words": [...],   # 정상 판정에 기여한 단어/피처
              "rule_contributions": {...} # 룰 피처 기여도
            }
        """
        from src.features.rule_features import get_rule_feature_columns
        rule_cols = set(get_rule_feature_columns())

        positive_words = []   # SHAP > 0: 피싱에 기여
        negative_words = []   # SHAP < 0: 정상에 기여
        rule_contributions: Dict[str, float] = {}

        for feat_name, shap_val in top_features:
            if abs(shap_val) < threshold:
                continue

            if feat_name in rule_cols:
                rule_contributions[feat_name] = round(float(shap_val), 4)
            else:
                # TF-IDF 단어 피처
                if shap_val > 0:
                    positive_words.append((feat_name, round(float(shap_val), 4)))
                else:
                    negative_words.append((feat_name, round(float(shap_val), 4)))

        return {
            "positive_words": positive_words[:8],
            "negative_words": negative_words[:5],
            "rule_contributions": rule_contributions,
        }

    # ── 시각화 (노트북 전용) ──────────────────

    def plot_waterfall(self, X_single, max_display: int = 15):
        """단일 샘플에 대한 SHAP Waterfall Plot (노트북에서 사용)"""
        shap_vals = self._explainer(X_single)
        if hasattr(shap_vals, "__getitem__"):
            self.shap.plots.waterfall(shap_vals[0], max_display=max_display)
        else:
            logger.warning("Waterfall plot not available for this model type.")

    def plot_summary(self, X, max_display: int = 20):
        """전체 데이터셋 SHAP Summary Plot (노트북에서 사용)"""
        shap_vals = self.get_shap_values(X)
        self.shap.summary_plot(
            shap_vals, X,
            feature_names=self.feature_names,
            max_display=max_display,
            plot_type="bar",
        )

    def plot_beeswarm(self, X, max_display: int = 20):
        """SHAP Beeswarm Plot (분포 시각화)"""
        shap_vals_obj = self._explainer(X)
        self.shap.plots.beeswarm(shap_vals_obj, max_display=max_display)


# ─────────────────────────────────────────────
# 키워드 하이라이팅
# ─────────────────────────────────────────────

def highlight_keywords_html(
    text: str,
    top_words: List[Tuple[str, float]],
    color_positive: str = "#ff6b6b",   # 피싱 기여 단어 → 빨간색
    color_negative: str = "#51cf66",   # 정상 기여 단어 → 초록색
) -> str:
    """
    SHAP 상위 기여 단어를 HTML mark 태그로 강조 표시.
    Streamlit에서 st.markdown(unsafe_allow_html=True)로 렌더링.

    Args:
        text: 원본 이메일 텍스트
        top_words: [(word, shap_value), ...]
    Returns:
        HTML 문자열
    """
    import re
    import html as html_lib

    escaped = html_lib.escape(text)

    for word, shap_val in top_words:
        if len(word) < 3:  # 너무 짧은 단어 제외
            continue
        color = color_positive if shap_val > 0 else color_negative
        escaped = re.sub(
            rf"\b({re.escape(word)})\b",
            f'<mark style="background-color:{color};padding:1px 3px;border-radius:3px;">\\1</mark>',
            escaped,
            flags=re.IGNORECASE,
        )

    return f'<div style="font-family:monospace;line-height:1.8;">{escaped}</div>'
