"""
룰 기반 자연어 설명 생성 모듈

ML 모델의 분류 결과와 룰 피처 값을 분석하여
"왜 이 메일이 피싱인지" 인간이 읽을 수 있는 근거 문장 목록을 반환.
"""

from typing import Any, Dict, List


_RULES = [

    (
        "impersonation_score",
        lambda v: v >= 1,
        "⚠️ 본문에 공식 기관/서비스명이 언급되었으나 발신 도메인이 공식 도메인과 다릅니다 (사칭 의심)",
        "high",
    ),
    (
        "credential_request",
        lambda v: v == 1,
        "⚠️ 비밀번호, 계좌번호, 개인정보 입력을 요구하는 표현이 감지되었습니다",
        "high",
    ),
    (
        "has_suspicious_url",
        lambda v: v == 1,
        "⚠️ 수상한 도메인 확장자(.tk, .ml, .xyz 등)를 가진 링크가 포함되어 있습니다",
        "high",
    ),
    (
        "suspicious_file_link",
        lambda v: v == 1,
        "⚠️ 실행파일/압축파일 다운로드를 유도하는 링크가 포함되어 있습니다 (악성코드 유포 가능성)",
        "high",
    ),
    (
        "has_url_obfuscation",
        lambda v: v == 1,
        "⚠️ URL 난독화 패턴(@, punycode, IP 직접 표기)이 감지되었습니다",
        "high",
    ),
    (
        "link_only_lure",
        lambda v: v == 1,
        "⚠️ 직접 정보요구 없이 링크 클릭만 유도하는 피싱 패턴이 감지되었습니다",
        "high",
    ),
    (
        "url_domain_mismatch",
        lambda v: v == 1,
        "⚠️ URL에 포함된 도메인이 언급된 브랜드/기관의 공식 도메인과 일치하지 않습니다",
        "high",
    ),
    (
        "threat_language",
        lambda v: v == 1,
        "⚠️ 법적 조치, 계정 해킹, 협박, 랜섬웨어 등 공포 유도 문구가 감지되었습니다",
        "high",
    ),
    (
        "unusual_payment_request",
        lambda v: v == 1,
        "⚠️ 상품권, 가상화폐, 송금 등 비정상 결제/송금 수단을 요구하는 표현이 감지되었습니다",
        "high",
    ),
    (
        "urgency_score",
        lambda v: v >= 2,
        "⚠️ 즉각적인 행동을 강요하는 긴급 유도 표현이 여러 개 감지되었습니다",
        "medium",
    ),
    (
        "money_request",
        lambda v: v == 1,
        "⚠️ 금전 이체, 상금, 유산 수령 등 금전 요구 패턴이 감지되었습니다",
        "medium",
    ),
    (
        "malware_lure_score",
        lambda v: v >= 1,
        "⚠️ 프로그램 설치/업데이트/실행을 유도하는 표현이 감지되었습니다",
        "medium",
    ),
    (
        "link_lure_score",
        lambda v: v >= 2,
        "⚠️ 문서 확인/접속/검토 등 링크 클릭 유도 표현이 반복적으로 감지되었습니다",
        "medium",
    ),
    (
        "attachment_lure",
        lambda v: v == 1,
        "⚠️ 첨부파일 열람 또는 첨부 문서 확인을 유도하는 표현이 감지되었습니다",
        "medium",
    ),
    (
        "business_lure_score",
        lambda v: v >= 1,
        "⚠️ 인보이스, 결제, 급여, 인사팀 등 업무성 위장 문구가 감지되었습니다",
        "medium",
    ),
    (
        "reward_offer",
        lambda v: v == 1,
        "⚠️ 경품, 보상, 과도한 혜택 제안 등 '너무 좋은 제안' 유형의 표현이 감지되었습니다",
        "medium",
    ),
    (
        "generic_greeting",
        lambda v: v == 1,
        "🔔 '고객님', 'Dear Customer' 같은 일반적 호칭이 사용되었습니다",
        "low",
    ),
    (
        "text_quality_score",
        lambda v: v >= 2,
        "🔔 문장 품질 저하, 오탈자, 과도한 강조 표현 등 비정상적인 작성 패턴이 감지되었습니다",
        "low",
    ),
    (
        "has_shortened_url",
        lambda v: v == 1,
        "🔔 단축 URL(bit.ly 등)이 포함되어 최종 이동 주소 확인이 필요합니다",
        "low",
    ),
    (
        "has_http_url",
        lambda v: v == 1,
        "🔔 암호화되지 않은 HTTP 링크(비HTTPS)가 포함되어 있습니다",
        "low",
    ),
    (
        "missing_reply_to",
        lambda v: v == 1,
        "🔔 Reply-To 헤더 정보가 없습니다",
        "low",
    ),
    (
        "url_count",
        lambda v: v >= 5,
        "🔔 이메일에 링크가 5개 이상 포함되어 있습니다",
        "low",
    ),
    (
        "subject_all_caps",
        lambda v: v == 1,
        "🔔 제목이 전부 대문자로 작성되어 있습니다 (클릭 유도 패턴)",
        "low",
    ),
    (
        "excessive_exclamation",
        lambda v: v == 1,
        "🔔 과도한 느낌표(!) 사용이 감지되었습니다",
        "low",
    ),
]

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def generate_rule_explanation(rule_features: Dict[str, Any], max_reasons: int = 8) -> List[Dict[str, str]]:
    triggered = []
    seen_texts = set()

    for feature_name, condition_fn, explanation_text, severity in _RULES:
        value = rule_features.get(feature_name)
        if value is None:
            continue
        try:
            if condition_fn(value) and explanation_text not in seen_texts:
                triggered.append({"text": explanation_text, "severity": severity})
                seen_texts.add(explanation_text)
        except Exception:
            continue

    triggered.sort(key=lambda x: _SEVERITY_ORDER.get(x["severity"], 9))
    return triggered[:max_reasons]


def format_explanation_text(reasons: List[Dict[str, str]], label: int, confidence: float, impersonated_brand: str = "") -> str:
    label_str = "🚨 피싱/위협 이메일" if label == 1 else "✅ 정상 이메일"
    conf_pct = round(confidence * 100, 1)

    lines = [f"[판정] {label_str}  (신뢰도: {conf_pct}%)", ""]

    if label == 1:
        if impersonated_brand:
            lines.append(f"[사칭 의심 브랜드] {impersonated_brand.upper()}")
            lines.append("")
        if reasons:
            lines.append("[판단 근거]")
            for r in reasons:
                lines.append(f"  {r['text']}")
        else:
            lines.append("[판단 근거] 모델이 위협 패턴을 학습 기반으로 감지하였습니다.")
    else:
        lines.append("[분석 결과] 명확한 피싱/사기 패턴이 감지되지 않았습니다.")
        if reasons:
            lines.append("")
            lines.append("[참고: 낮은 수준의 주의 신호]")
            for r in [r for r in reasons if r["severity"] == "low"]:
                lines.append(f"  {r['text']}")

    return "\n".join(lines)


def get_high_risk_features(rule_features: Dict[str, Any]) -> List[str]:
    high_risk = []
    for feature_name, condition_fn, _, severity in _RULES:
        if severity != "high":
            continue
        value = rule_features.get(feature_name)
        if value is not None:
            try:
                if condition_fn(value):
                    high_risk.append(feature_name)
            except Exception:
                continue
    return high_risk
