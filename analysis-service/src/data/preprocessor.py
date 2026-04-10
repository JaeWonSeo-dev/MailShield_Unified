"""
전처리 파이프라인 모듈

Raw DataFrame → Processed DataFrame
  - HTML 태그 제거
  - URL 추출 및 도메인 파싱
  - 발신자 도메인 파싱
  - 텍스트 정규화
  - text_combined 컬럼 생성
  - 학습/검증/테스트 분리
"""

import re
import logging
import warnings
from pathlib import Path
from typing import Tuple
from urllib.parse import urlparse

import pandas as pd
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

logger = logging.getLogger(__name__)

# URL 추출 정규식 (http/https/www 패턴)
_URL_PATTERN = re.compile(
    r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)",
    re.IGNORECASE,
)

# 이메일 주소에서 도메인 추출
_EMAIL_DOMAIN_PATTERN = re.compile(r"@([\w.\-]+)")

# HTML 엔티티 정리
_HTML_ENTITY_PATTERN = re.compile(r"&[a-zA-Z]+;|&#\d+;")

# 반복 공백/줄바꿈 정리
_WHITESPACE_PATTERN = re.compile(r"\s+")


# ─────────────────────────────────────────────
# 메인 전처리 파이프라인
# ─────────────────────────────────────────────

def preprocess(df: pd.DataFrame, text_max_length: int = 5000) -> pd.DataFrame:
    """
    원본 DataFrame을 전처리하여 학습용 DataFrame 반환

    입력 컬럼: email_id, source, subject, body, sender, reply_to, label_type, label
    추가 컬럼: sender_domain, reply_to_domain, urls, url_count,
               has_suspicious_url, text_combined, char_count
    """
    logger.info(f"Starting preprocessing for {len(df)} emails")

    df = df.copy()

    # 결측값 처리
    df["subject"]  = df["subject"].fillna("").astype(str)
    df["body"]     = df["body"].fillna("").astype(str)
    df["sender"]   = df["sender"].fillna("").astype(str)
    df["reply_to"] = df["reply_to"].fillna("").astype(str)

    # HTML 제거 및 텍스트 정규화
    df["subject_clean"] = df["subject"].apply(_clean_text)
    df["body_clean"]    = df["body"].apply(lambda t: _clean_text(t)[:text_max_length])

    # 발신자 도메인 추출
    df["sender_domain"]   = df["sender"].apply(_extract_email_domain)
    df["reply_to_domain"] = df["reply_to"].apply(_extract_email_domain)

    # URL 추출
    df["urls"] = df["body"].apply(_extract_urls)
    df["url_count"] = df["urls"].apply(len)
    df["has_suspicious_url"] = df["urls"].apply(_has_suspicious_url)

    # text_combined: 모델 입력용 통합 텍스트
    df["text_combined"] = df["subject_clean"] + " " + df["body_clean"]
    df["text_combined"] = df["text_combined"].apply(
        lambda t: _whitespace_normalize(t)
    )

    # 문자 수
    df["char_count"] = df["text_combined"].apply(len)

    # 빈 텍스트 제거
    before = len(df)
    df = df[df["text_combined"].str.strip().str.len() > 10].reset_index(drop=True)
    logger.info(f"Removed {before - len(df)} empty/short emails")

    logger.info(f"Preprocessing complete: {len(df)} emails")
    return df


# ─────────────────────────────────────────────
# 데이터 분리
# ─────────────────────────────────────────────

def split_dataset(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    random_seed: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Stratified split: train / val / test
    """
    test_ratio = 1.0 - train_ratio - val_ratio
    assert test_ratio > 0, "train_ratio + val_ratio must be less than 1.0"

    train_df, temp_df = train_test_split(
        df,
        test_size=(val_ratio + test_ratio),
        random_state=random_seed,
        stratify=df["label"],
    )
    val_size_adjusted = val_ratio / (val_ratio + test_ratio)
    val_df, test_df = train_test_split(
        temp_df,
        test_size=(1 - val_size_adjusted),
        random_state=random_seed,
        stratify=temp_df["label"],
    )

    logger.info(
        f"Split: train={len(train_df)}, val={len(val_df)}, test={len(test_df)}"
    )
    return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)


def save_splits(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    output_dir: str,
) -> None:
    """전처리된 분리 데이터를 CSV로 저장"""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    train_df.to_csv(out / "train.csv", index=False)
    val_df.to_csv(out / "val.csv",   index=False)
    test_df.to_csv(out / "test.csv",  index=False)
    logger.info(f"Saved splits to {output_dir}")


# ─────────────────────────────────────────────
# 내부 유틸리티 함수
# ─────────────────────────────────────────────

def _clean_text(text: str) -> str:
    """HTML 제거 + 텍스트 정규화. HTML 태그가 있을 때만 BeautifulSoup 사용."""
    # HTML 태그가 있을 때만 파싱 (속도 최적화)
    if re.search(r"<[a-zA-Z][^>]*>", text):
        try:
            soup = BeautifulSoup(text, "lxml")
            text = soup.get_text(separator=" ")
        except Exception:
            pass
    # HTML 엔티티 정리
    text = _HTML_ENTITY_PATTERN.sub(" ", text)
    # 제어 문자 제거
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    # 반복 공백 정리
    text = _whitespace_normalize(text)
    return text.strip()


def _whitespace_normalize(text: str) -> str:
    return _WHITESPACE_PATTERN.sub(" ", text).strip()


def _extract_email_domain(address: str) -> str:
    """이메일 주소에서 도메인 추출. 예: 'user@paypal.com' → 'paypal.com'"""
    if not address:
        return ""
    match = _EMAIL_DOMAIN_PATTERN.search(address)
    return match.group(1).lower().strip() if match else ""


def _extract_urls(text: str) -> list:
    """텍스트에서 URL 목록 추출"""
    return _URL_PATTERN.findall(text)


_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".download", ".zip"
}


def _has_suspicious_url(urls: list) -> bool:
    """수상한 TLD를 가진 URL이 포함되어 있는지 여부"""
    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc.lower()
            if any(hostname.endswith(tld) for tld in _SUSPICIOUS_TLDS):
                return True
        except Exception:
            continue
    return False


# ─────────────────────────────────────────────
# CLI 실행 지원
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import yaml
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    config_path = Path(__file__).parents[2] / "config.yaml"
    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # 데이터 로드
    sys.path.insert(0, str(Path(__file__).parents[2]))
    from src.data.loader import load_all_datasets

    raw_dir = config["paths"]["raw_data_dir"]
    processed_dir = config["paths"]["processed_data_dir"]

    max_per_source = config["data"].get("max_samples_per_class", None)
    df_raw = load_all_datasets(raw_dir, max_samples_per_source=max_per_source)
    df_processed = preprocess(df_raw, text_max_length=config["data"]["text_max_length"])

    logger.info(f"Full dataset: {len(df_processed)} | {df_processed['label'].value_counts().to_dict()}")

    train_df, val_df, test_df = split_dataset(
        df_processed,
        train_ratio=config["data"]["train_ratio"],
        val_ratio=config["data"]["val_ratio"],
        random_seed=config["data"]["random_seed"],
    )
    save_splits(train_df, val_df, test_df, processed_dir)
    print(f"전처리 완료! train={len(train_df)}, val={len(val_df)}, test={len(test_df)}")
