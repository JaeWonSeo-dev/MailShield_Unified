"""
룰 기반 피처 엔지니어링 모듈

이메일 텍스트/헤더로부터 피싱 탐지에 특화된 구조적 피처를 추출.
각 피처는 설명 모듈에서 자연어 판단 근거로 직접 활용됨.

개선 사항:
  - 단건 추론 / 배치 학습 피처 계산 로직 일관성 강화
  - config.yaml 기반 키워드 / suspicious TLD 로드 지원
  - url_domain_mismatch가 학습 파이프라인에서도 실제 계산되도록 수정
  - 기관 가이드 기반 추가 신호 확장
    * generic greeting
    * reward / too-good-to-be-true
    * unusual payment method
    * attachment lure
    * invoice / HR / payroll lure
    * simple text quality heuristic
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

import pandas as pd
import yaml

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "config.yaml"

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "rebrand.ly"}
SUSPICIOUS_FILE_EXTS = {".exe", ".msi", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1", ".iso", ".zip", ".rar"}
COMMON_TYPOS = {
    "verfy", "accout", "passwrod", "suspnded", "immediatly", "secruity",
    "recieve", "confrim", "updatre", "paymnet", "logn", "documnt"
}

IMPERSONATION_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "bank": None,
    "irs": "irs.gov",
    "fedex": "fedex.com",
    "dhl": "dhl.com",
    "naver": "naver.com",
    "kakao": "kakao.com",
    "coupang": "coupang.com",
    "gov": None,
    "정부24": None,
    "국세청": None,
    "신한": None,
    "국민": None,
}

_URL_PATTERN = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)", re.IGNORECASE)
_EMAIL_DOMAIN_RE = re.compile(r"@([\w.\-]+)")
_IPV4_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)
_UPPER_TOKEN_RE = re.compile(r"\b[A-Z]{4,}\b")
_MULTISPACE_RE = re.compile(r"\s{2,}")


def _load_rule_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return yaml.safe_load(f).get("rule_features", {}) or {}
    except Exception as e:
        logger.warning(f"Failed to load rule_features config: {e}")
        return {}


_RULE_CONFIG = _load_rule_config()


def _escape_as_phrase_pattern(keyword: str) -> str:
    escaped = re.escape(keyword.strip())
    if re.search(r"[a-zA-Z0-9]", keyword):
        return rf"\b{escaped}\b"
    return escaped


def _merge_patterns(config_key: str, fallback: List[str]) -> List[str]:
    values = _RULE_CONFIG.get(config_key, []) or []
    patterns = [_escape_as_phrase_pattern(v) for v in values if str(v).strip()]
    return patterns or fallback


URGENCY_KEYWORDS = _merge_patterns(
    "urgency_keywords_en",
    [
        r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bexpires today\b",
        r"\blast chance\b", r"\bfinal notice\b", r"\baccount.*suspend", r"\bverify.*account\b",
        r"\bclick here immediately\b", r"\blimited time\b", r"\byour account.*terminated\b",
    ],
) + _merge_patterns(
    "urgency_keywords_ko",
    [r"즉시", r"긴급", r"지금 바로", r"오늘 안에", r"마지막 경고"],
)

CREDENTIAL_KEYWORDS = _merge_patterns(
    "credential_keywords_en",
    [
        r"\bpassword\b", r"\bsocial security\b", r"\bcredit card\b", r"\bbank account\b",
        r"\bconfirm.*identity\b", r"\bverify.*information\b", r"\benter.*details\b",
        r"\blogin.*credentials\b", r"\bpin\b", r"\bcvv\b",
    ],
) + _merge_patterns(
    "credential_keywords_ko",
    [r"비밀번호", r"계좌번호", r"주민번호", r"개인정보 입력"],
)

MONEY_KEYWORDS = _merge_patterns(
    "money_keywords_en",
    [
        r"\bmillion\b", r"\bwire transfer\b", r"\bwestern union\b", r"\binheritance\b",
        r"\blottery\b", r"\bunclaimed fund\b", r"\bprize\b", r"\breward\b",
        r"\badvance fee\b", r"\btransaction fee\b",
    ],
)

THREAT_KEYWORDS = _merge_patterns(
    "threat_keywords_en",
    [
        r"\blegal action\b", r"\barrest\b", r"\bpenalty\b", r"\blawsuit\b",
        r"\bhacked your\b", r"\bwe have.*video\b", r"\bblackmail\b",
        r"\bexpose\b", r"\byour files\b", r"\bransom\b",
    ],
)

GENERIC_GREETINGS = _merge_patterns(
    "generic_greetings_en",
    [r"\bdear customer\b", r"\bdear user\b", r"\bvalued customer\b", r"\bdear member\b"],
) + _merge_patterns(
    "generic_greetings_ko",
    [r"고객님", r"회원님", r"사용자님"],
)

REWARD_KEYWORDS = _merge_patterns(
    "reward_keywords_en",
    [r"\bclaim your prize\b", r"\blottery winner\b", r"\breward\b", r"\bbonus\b", r"\bexclusive offer\b"],
) + _merge_patterns(
    "reward_keywords_ko",
    [r"당첨", r"경품", r"보상", r"혜택"],
)

PAYMENT_KEYWORDS = _merge_patterns(
    "payment_keywords_en",
    [r"\bgift card\b", r"\bbitcoin\b", r"\bcrypto\b", r"\bwire transfer\b", r"\bbank transfer\b", r"\bwestern union\b"],
) + _merge_patterns(
    "payment_keywords_ko",
    [r"상품권", r"기프트카드", r"비트코인", r"가상화폐", r"송금", r"계좌이체"],
)

ATTACHMENT_KEYWORDS = _merge_patterns(
    "attachment_keywords_en",
    [r"\battached invoice\b", r"\bsee attached\b", r"\bopen attachment\b", r"\battached file\b", r"\bdownload the attachment\b"],
) + _merge_patterns(
    "attachment_keywords_ko",
    [r"첨부파일", r"첨부 문서", r"첨부된 파일", r"붙임파일"],
)

BUSINESS_LURE_KEYWORDS = _merge_patterns(
    "business_lure_keywords_en",
    [r"\binvoice\b", r"\bpayment\b", r"\bpayroll\b", r"\bhr\b", r"\bhuman resources\b", r"\bpurchase order\b", r"\bsalary\b"],
) + _merge_patterns(
    "business_lure_keywords_ko",
    [r"세금계산서", r"청구서", r"급여", r"인사팀", r"결제", r"구매 요청"],
)

LINK_LURE_KEYWORDS = [
    r"\bclick\b", r"\bopen\b", r"\bview\b", r"\breview\b", r"\bcheck\b",
    r"\blogin\b", r"\bsign in\b", r"\bverify\b", r"\bconfirm\b", r"\bportal\b",
    r"\bshared document\b", r"\baccess\b", r"\bdownload\b",
    r"클릭", r"확인", r"접속", r"로그인", r"검토", r"다운로드",
]

MALWARE_LURE_KEYWORDS = [
    r"\bdownload\b", r"\binstall\b", r"\brun\b", r"\benable macro\b", r"\bupdate now\b",
    r"\bsecurity update\b", r"\bpatch\b", r"\bremote tool\b", r"\bviewer\b",
    r"다운로드", r"설치", r"실행", r"업데이트", r"매크로", r"보안 패치",
]

SUSPICIOUS_TLDS = set(_RULE_CONFIG.get("suspicious_tlds", [])) or {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".download", ".zip"
}


def extract_rule_features(row: Dict[str, Any]) -> Dict[str, Any]:
    text = str(row.get("text_combined", "")).lower()
    subject = str(row.get("subject", "")).lower()
    sender = str(row.get("sender", "")).lower()
    reply_to = str(row.get("reply_to", "")).lower()
    body_raw = str(row.get("body", ""))
    urls = row.get("urls", []) or []
    extracted_urls = urls if urls else _URL_PATTERN.findall(body_raw)

    features: Dict[str, Any] = {}

    sender_domain = _extract_domain_from_email(sender)
    reply_domain = _extract_domain_from_email(reply_to)
    # 참고용 헤더 이상 신호는 계산하되, 현재 피싱 판정 기준/학습 피처에서는 제외한다.
    features["sender_domain_mismatch"] = int(bool(reply_domain) and reply_domain != sender_domain)
    features["missing_reply_to"] = int(not bool(reply_to.strip()))

    impersonation_score = 0
    impersonated_brand = ""
    for brand, official_domain in IMPERSONATION_BRANDS.items():
        if brand in text and official_domain and sender_domain and official_domain not in sender_domain:
            impersonation_score += 1
            impersonated_brand = impersonated_brand or brand
    features["impersonation_score"] = min(impersonation_score, 5)
    features["impersonated_brand"] = impersonated_brand

    features["url_count"] = len(extracted_urls)
    features["has_http_url"] = int(any(u.lower().startswith("http://") for u in extracted_urls))
    features["has_suspicious_url"] = int(_check_suspicious_tld(extracted_urls))
    features["has_shortened_url"] = int(_check_shortener_url(extracted_urls))
    features["has_url_obfuscation"] = int(_check_url_obfuscation(extracted_urls))
    features["suspicious_file_link"] = int(_check_suspicious_file_link(extracted_urls))
    features["url_domain_mismatch"] = int(_check_url_brand_mismatch(extracted_urls, text))

    features["urgency_score"] = min(_count_pattern_matches(text, URGENCY_KEYWORDS), 10)
    features["credential_request"] = int(_count_pattern_matches(text, CREDENTIAL_KEYWORDS) > 0)
    features["money_request"] = int(_count_pattern_matches(text, MONEY_KEYWORDS) > 0)
    features["threat_language"] = int(_count_pattern_matches(text, THREAT_KEYWORDS) > 0)
    features["generic_greeting"] = int(_count_pattern_matches(text, GENERIC_GREETINGS) > 0)
    features["reward_offer"] = int(_count_pattern_matches(text, REWARD_KEYWORDS) > 0)
    features["unusual_payment_request"] = int(_count_pattern_matches(text, PAYMENT_KEYWORDS) > 0)
    features["attachment_lure"] = int(_count_pattern_matches(text, ATTACHMENT_KEYWORDS) > 0)
    features["business_lure_score"] = min(_count_pattern_matches(text, BUSINESS_LURE_KEYWORDS), 10)
    features["link_lure_score"] = min(_count_pattern_matches(text, LINK_LURE_KEYWORDS), 10)
    features["malware_lure_score"] = min(_count_pattern_matches(text, MALWARE_LURE_KEYWORDS), 10)
    features["link_only_lure"] = int(
        len(extracted_urls) > 0 and features["link_lure_score"] >= 2 and features["credential_request"] == 0
    )

    features["subject_all_caps"] = int(subject.upper() == subject and len(subject) > 5)
    features["excessive_exclamation"] = int(body_raw.count("!") > 5)
    features["excessive_question"] = int(body_raw.count("?") > 5)
    features["has_html_tag"] = int(bool(re.search(r"<[a-z]+[\s>]", body_raw, re.IGNORECASE)))
    features["text_quality_score"] = _compute_text_quality_score(subject, body_raw)

    features["rule_risk_score"] = _compute_rule_risk_score(features)
    return features


def add_rule_features(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("Extracting rule-based features with parity-safe row processing...")
    df = df.copy()

    rows = []
    for _, row in df.iterrows():
        row_dict = row.to_dict()
        if not row_dict.get("urls"):
            row_dict["urls"] = _URL_PATTERN.findall(str(row_dict.get("body", "")))
        rows.append(extract_rule_features(row_dict))

    features_df = pd.DataFrame(rows, index=df.index)
    for col in get_rule_feature_columns():
        if col not in features_df.columns:
            features_df[col] = 0

    for col in get_rule_feature_columns():
        df[col] = features_df[col]

    logger.info(f"Rule features added: {get_rule_feature_columns()}")
    return df


def get_rule_feature_columns() -> List[str]:
    return [
        "missing_reply_to",
        "impersonation_score",
        "url_count",
        "has_http_url",
        "has_suspicious_url",
        "has_shortened_url",
        "has_url_obfuscation",
        "suspicious_file_link",
        "url_domain_mismatch",
        "urgency_score",
        "credential_request",
        "money_request",
        "threat_language",
        "generic_greeting",
        "reward_offer",
        "unusual_payment_request",
        "attachment_lure",
        "business_lure_score",
        "link_lure_score",
        "malware_lure_score",
        "link_only_lure",
        "subject_all_caps",
        "excessive_exclamation",
        "excessive_question",
        "has_html_tag",
        "text_quality_score",
        "rule_risk_score",
    ]


def _compute_rule_risk_score(features: Dict[str, Any]) -> int:
    risk = (
        int(features.get("urgency_score", 0)) * 2
        + int(features.get("credential_request", 0)) * 3
        + int(features.get("money_request", 0)) * 2
        + int(features.get("threat_language", 0)) * 2
        + int(features.get("impersonation_score", 0)) * 2
        + int(features.get("has_suspicious_url", 0)) * 2
        + int(features.get("has_shortened_url", 0))
        + int(features.get("has_url_obfuscation", 0)) * 2
        + int(features.get("suspicious_file_link", 0)) * 3
        + int(features.get("link_only_lure", 0)) * 2
        + min(int(features.get("malware_lure_score", 0)), 2) * 2
        + int(features.get("url_domain_mismatch", 0)) * 2
        + int(features.get("generic_greeting", 0))
        + int(features.get("reward_offer", 0)) * 2
        + int(features.get("unusual_payment_request", 0)) * 3
        + int(features.get("attachment_lure", 0)) * 2
        + min(int(features.get("business_lure_score", 0)), 2)
        + min(int(features.get("text_quality_score", 0)), 2)
    )
    return min(risk, 10)


def _extract_domain_from_email(address: str) -> str:
    match = _EMAIL_DOMAIN_RE.search(address or "")
    return match.group(1).lower().strip() if match else ""


def _count_pattern_matches(text: str, patterns: List[str]) -> int:
    count = 0
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            count += 1
    return count


def _normalize_hostname(url: str) -> str:
    parsed = urlparse(url if str(url).startswith(("http://", "https://")) else f"http://{url}")
    hostname = parsed.netloc.lower() or parsed.path.lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def _compute_text_quality_score(subject: str, body: str) -> int:
    text = f"{subject} {body}".strip()
    lowered = text.lower()
    score = 0

    typo_hits = sum(1 for typo in COMMON_TYPOS if typo in lowered)
    if typo_hits >= 1:
        score += 1
    if len(_UPPER_TOKEN_RE.findall(text)) >= 3:
        score += 1
    if _MULTISPACE_RE.search(text):
        score += 1
    if re.search(r"[!?]{4,}", text):
        score += 1
    return min(score, 3)


def _check_suspicious_tld(urls: List[str]) -> bool:
    for url in urls:
        try:
            hostname = _normalize_hostname(url)
            if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
                return True
        except Exception:
            continue
    return False


def _check_url_brand_mismatch(urls: List[str], text: str) -> bool:
    for brand, official_domain in IMPERSONATION_BRANDS.items():
        if brand not in text or not official_domain:
            continue
        for url in urls:
            try:
                hostname = _normalize_hostname(url)
                if brand in hostname and official_domain not in hostname:
                    return True
            except Exception:
                continue
    return False


def _check_shortener_url(urls: List[str]) -> bool:
    for url in urls:
        try:
            if _normalize_hostname(url) in SHORTENER_DOMAINS:
                return True
        except Exception:
            continue
    return False


def _check_url_obfuscation(urls: List[str]) -> bool:
    for url in urls:
        lowered = str(url).lower()
        if "@" in lowered or "xn--" in lowered:
            return True
        if _IPV4_URL_RE.search(lowered):
            return True
    return False


def _check_suspicious_file_link(urls: List[str]) -> bool:
    for url in urls:
        lowered = str(url).lower()
        for ext in SUSPICIOUS_FILE_EXTS:
            if re.search(rf"{re.escape(ext)}(?:\?|$|[\s/#])", lowered):
                return True
    return False
