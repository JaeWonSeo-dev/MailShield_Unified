"""
데이터셋 로더 모듈

지원 데이터셋 (data/raw/phishing_kaggle/ 폴더):
  - phishing_email.csv  : text_combined, label (0=ham, 1=phishing)
  - Nazario.csv         : sender,subject,body,urls,label (모두 label=1, phishing)
  - CEAS_08.csv         : sender,subject,body,urls,label (spam/phishing 혼합)
  - Enron.csv           : subject,body,label (0=ham, 1=spam)
  - Ling.csv            : subject,body,label (0=ham, 1=spam)
  - Nigerian_Fraud.csv  : sender,subject,body,urls,label (모두 label=1, fraud)
  - SpamAssasin.csv     : sender,subject,body,urls,label (0=ham, 1=spam)

  - data/raw/enron/emails.csv : raw 이메일 포맷 (file, message 컬럼)
"""

import email
import email.message
import logging
from pathlib import Path
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# 구조화된 CSV 로더 (phishing_kaggle 폴더 공통)
# ─────────────────────────────────────────────

def _load_structured_csv(
    csv_path: Path,
    source_name: str,
    label_type_map: dict,  # {0: "ham", 1: "phishing"} 등
    max_samples: Optional[int] = None,
) -> pd.DataFrame:
    """
    subject, body, label 컬럼을 가진 구조화된 CSV 공통 로더.
    sender, urls 컬럼이 있으면 함께 읽음.
    """
    df = pd.read_csv(csv_path, nrows=max_samples)
    records = []
    for _, row in df.iterrows():
        label = int(row["label"])
        label_type = label_type_map.get(label, "unknown")
        if label_type == "unknown":
            continue

        subject = str(row.get("subject", "") or "")
        body = str(row.get("body", "") or "")
        sender = str(row.get("sender", "") or "")
        urls = str(row.get("urls", "") or "")

        records.append({
            "source":     source_name,
            "subject":    subject,
            "body":       body,
            "sender":     sender,
            "reply_to":   "",
            "urls_raw":   urls,
            "label_type": label_type,
            "label":      label,
        })
    logger.info(f"Loaded {len(records)} rows from {csv_path.name}")
    return pd.DataFrame(records)


# ─────────────────────────────────────────────
# 개별 파일 로더
# ─────────────────────────────────────────────

def load_phishing_email_csv(data_dir: str, max_samples: Optional[int] = None) -> pd.DataFrame:
    """
    phishing_email.csv: text_combined(합쳐진 본문), label(0=ham, 1=phishing)
    """
    csv_path = Path(data_dir) / "phishing_kaggle" / "phishing_email.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Not found: {csv_path}")

    df = pd.read_csv(csv_path, nrows=max_samples)
    label_type_map = {0: "ham", 1: "phishing"}
    records = []
    for _, row in df.iterrows():
        label = int(row["label"])
        records.append({
            "source":     "phishing_email_csv",
            "subject":    "",
            "body":       str(row.get("text_combined", "") or ""),
            "sender":     "",
            "reply_to":   "",
            "urls_raw":   "",
            "label_type": label_type_map.get(label, "unknown"),
            "label":      label,
        })
    logger.info(f"Loaded {len(records)} rows from phishing_email.csv")
    return pd.DataFrame(records)


def load_nazario(data_dir: str, max_samples: Optional[int] = None) -> pd.DataFrame:
    """Nazario.csv: 피싱 전용 (label=1)"""
    csv_path = Path(data_dir) / "phishing_kaggle" / "Nazario.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Not found: {csv_path}")
    return _load_structured_csv(csv_path, "nazario", {1: "phishing"}, max_samples)


def load_ceas08(data_dir: str, max_samples: Optional[int] = None) -> pd.DataFrame:
    """CEAS_08.csv: 0=ham, 1=spam/phishing"""
    csv_path = Path(data_dir) / "phishing_kaggle" / "CEAS_08.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Not found: {csv_path}")
    return _load_structured_csv(csv_path, "ceas08", {0: "ham", 1: "spam"}, max_samples)


def load_enron_structured(data_dir: str, max_samples: Optional[int] = None) -> pd.DataFrame:
    """Enron.csv (phishing_kaggle 폴더): subject+body+label, 0=ham, 1=spam"""
    csv_path = Path(data_dir) / "phishing_kaggle" / "Enron.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Not found: {csv_path}")
    return _load_structured_csv(csv_path, "enron_structured", {0: "ham", 1: "spam"}, max_samples)


def load_ling(data_dir: str, max_samples: Optional[int] = None) -> pd.DataFrame:
    """Ling.csv: 0=ham, 1=spam"""
    csv_path = Path(data_dir) / "phishing_kaggle" / "Ling.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Not found: {csv_path}")
    return _load_structured_csv(csv_path, "ling", {0: "ham", 1: "spam"}, max_samples)


def load_nigerian_fraud_csv(data_dir: str, max_samples: Optional[int] = None) -> pd.DataFrame:
    """Nigerian_Fraud.csv: 사기 메일 전용 (label=1)"""
    csv_path = Path(data_dir) / "phishing_kaggle" / "Nigerian_Fraud.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Not found: {csv_path}")
    return _load_structured_csv(csv_path, "nigerian_fraud", {1: "fraud"}, max_samples)


def load_spamassassin_csv(data_dir: str, max_samples: Optional[int] = None) -> pd.DataFrame:
    """SpamAssasin.csv: 0=ham, 1=spam"""
    csv_path = Path(data_dir) / "phishing_kaggle" / "SpamAssasin.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Not found: {csv_path}")
    return _load_structured_csv(csv_path, "spamassassin", {0: "ham", 1: "spam"}, max_samples)


def load_enron_raw(data_dir: str, max_samples: Optional[int] = 10000) -> pd.DataFrame:
    """
    Enron raw CSV (data/raw/enron/emails.csv): file, message 컬럼 (원시 이메일 포맷)
    ham 데이터 추가 확보용. phishing_kaggle/Enron.csv가 있으면 이건 건너뛰어도 됨.
    """
    csv_path = Path(data_dir) / "enron" / "emails.csv"
    if not csv_path.exists():
        raise FileNotFoundError(f"Not found: {csv_path}")

    logger.info(f"Loading raw Enron from {csv_path} (max {max_samples})")
    df = pd.read_csv(csv_path, nrows=max_samples)

    records = []
    for _, row in df.iterrows():
        try:
            msg = email.message_from_string(str(row["message"]))
            body = _extract_body(msg)
            records.append({
                "source":     "enron_raw",
                "subject":    msg.get("Subject", ""),
                "body":       body,
                "sender":     msg.get("From", ""),
                "reply_to":   msg.get("Reply-To", ""),
                "urls_raw":   "",
                "label_type": "ham",
                "label":      0,
            })
        except Exception as e:
            logger.debug(f"Enron raw parse error: {e}")
            continue

    logger.info(f"Loaded {len(records)} raw Enron emails")
    return pd.DataFrame(records)


# ─────────────────────────────────────────────
# 통합 로더
# ─────────────────────────────────────────────

def load_all_datasets(
    raw_data_dir: str,
    max_samples_per_source: Optional[int] = None,
) -> pd.DataFrame:
    """
    사용 가능한 모든 데이터셋을 로드하여 하나의 DataFrame으로 병합.

    우선적으로 phishing_kaggle/ 폴더의 구조화된 CSV를 사용.
    raw Enron CSV (1.7GB)는 선택적으로 추가 가능.
    """
    loaders = [
        ("Nazario",        load_nazario),
        ("CEAS_08",        load_ceas08),
        ("Enron_struct",   load_enron_structured),
        ("Ling",           load_ling),
        ("Nigerian_Fraud", load_nigerian_fraud_csv),
        ("SpamAssassin",   load_spamassassin_csv),
        ("phishing_email", load_phishing_email_csv),
    ]

    dfs = []
    for name, loader_fn in loaders:
        try:
            df = loader_fn(raw_data_dir, max_samples=max_samples_per_source)
            if not df.empty:
                dfs.append(df)
        except FileNotFoundError as e:
            logger.warning(f"[{name}] {e}")
        except Exception as e:
            logger.warning(f"[{name}] load failed: {e}")

    if not dfs:
        raise RuntimeError("No dataset loaded. Check data/raw/ directory.")

    combined = pd.concat(dfs, ignore_index=True)
    combined["email_id"] = [f"email_{i:06d}" for i in range(len(combined))]

    logger.info(
        f"Total loaded: {len(combined)} emails\n"
        f"Label distribution:\n{combined['label_type'].value_counts().to_string()}"
    )
    return combined


# ─────────────────────────────────────────────
# 내부 유틸리티
# ─────────────────────────────────────────────

def _extract_body(msg: email.message.Message) -> str:
    """이메일 메시지에서 텍스트 본문 추출"""
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body_parts.append(_safe_decode(payload))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_parts.append(_safe_decode(payload))
    return " ".join(body_parts)


def _safe_decode(b: bytes) -> str:
    """바이트를 안전하게 문자열로 디코딩"""
    for encoding in ("utf-8", "latin-1", "cp1252", "ascii"):
        try:
            return b.decode(encoding)
        except (UnicodeDecodeError, AttributeError):
            continue
    return b.decode("utf-8", errors="replace")


def _find_column(df: pd.DataFrame, candidates: list) -> Optional[str]:
    """가능한 컬럼명 후보 중 실제 존재하는 컬럼 반환"""
    for c in candidates:
        if c in df.columns:
            return c
    return None
