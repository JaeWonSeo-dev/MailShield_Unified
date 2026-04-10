"""
피싱 이메일 탐지 시스템 - Streamlit 데모 앱

실행 방법:
    streamlit run app/streamlit_app.py
"""

import email
import sys
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st
import yaml

# 프로젝트 루트를 sys.path에 추가
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from src.data.preprocessor import _extract_email_domain, _extract_urls
from src.explainability.rule_explainer import generate_rule_explanation
from src.features.rule_features import SUSPICIOUS_TLDS, extract_rule_features


st.set_page_config(
    page_title="피싱 이메일 탐지 AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def inject_custom_css() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Sans+KR:wght@400;500;700&display=swap');
        :root {
            --bg-warm-1: #f7efe2;
            --bg-warm-2: #f2f6f3;
            --ink-main: #1f2a24;
            --ink-muted: #506057;
            --accent-safe: #1a7f46;
            --accent-risk: #b12e2e;
            --card-bg: rgba(255, 255, 255, 0.78);
            --card-border: rgba(31, 42, 36, 0.14);
        }
        .stApp {
            font-family: 'IBM Plex Sans KR', sans-serif;
            background:
                radial-gradient(1100px 500px at -10% -20%, rgba(210, 165, 92, 0.26), transparent 60%),
                radial-gradient(900px 420px at 110% 0%, rgba(58, 126, 89, 0.20), transparent 58%),
                linear-gradient(135deg, var(--bg-warm-1), var(--bg-warm-2));
            color: var(--ink-main);
        }
        h1, h2, h3 {
            font-family: 'Space Grotesk', sans-serif;
            letter-spacing: -0.02em;
        }
        div[data-testid="stMetric"] {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 14px;
            padding: 10px 12px;
        }
        .hero-box {
            background: linear-gradient(120deg, rgba(255,255,255,0.90), rgba(255,255,255,0.72));
            border: 1px solid var(--card-border);
            border-radius: 18px;
            padding: 1.15rem 1.2rem;
            margin-bottom: 0.8rem;
            box-shadow: 0 10px 30px rgba(25, 36, 30, 0.08);
        }
        .status-pill {
            display: inline-block;
            border-radius: 999px;
            padding: 0.25rem 0.7rem;
            font-size: 0.84rem;
            font-weight: 600;
            margin-bottom: 0.35rem;
            border: 1px solid transparent;
        }
        .status-ok {
            color: #124f2e;
            background: #dff3e8;
            border-color: #b8e4c9;
        }
        .status-warn {
            color: #824300;
            background: #fff0d7;
            border-color: #f4d5a0;
        }
        .risk-panel {
            border-radius: 16px;
            border: 1px solid var(--card-border);
            background: var(--card-bg);
            padding: 0.95rem 1rem;
            margin-bottom: 0.75rem;
        }
        .risk-high { border-left: 5px solid #b12e2e; }
        .risk-medium { border-left: 5px solid #af6d1c; }
        .risk-low { border-left: 5px solid #2d6a8f; }
        .small-note {
            color: var(--ink-muted);
            font-size: 0.92rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def parse_uploaded_eml(uploaded_file) -> dict:
    if uploaded_file is None:
        return {"sender": "", "reply_to": "", "subject": "", "body": ""}

    raw = uploaded_file.getvalue()
    msg = email.message_from_bytes(raw)

    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in {"text/plain", "text/html"}:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_parts.append(payload.decode(charset, errors="replace"))
                    except LookupError:
                        body_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                body_parts.append(payload.decode(charset, errors="replace"))
            except LookupError:
                body_parts.append(payload.decode("utf-8", errors="replace"))

    return {
        "sender": str(msg.get("From", "") or ""),
        "reply_to": str(msg.get("Reply-To", "") or ""),
        "subject": str(msg.get("Subject", "") or ""),
        "body": "\n".join(body_parts).strip(),
    }


@st.cache_data
def load_config():
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


@st.cache_resource
def load_artifacts(model_name: str):
    model_dir = ROOT / "models" / "saved"
    model_file_map = {
        "xgboost": "xgboost_model.pkl",
        "random_forest": "random_forest_model.pkl",
        "logistic_regression": "lr_model.pkl",
        "lr": "lr_model.pkl",
    }
    model_filename = model_file_map.get(model_name, "xgboost_model.pkl")
    model_path = model_dir / model_filename
    extractor_path = model_dir / "feature_extractor.pkl"

    if not model_path.exists() or not extractor_path.exists():
        return None, None

    return joblib.load(model_path), joblib.load(extractor_path)


def build_input_row(subject: str, body: str, sender: str, reply_to: str) -> tuple[dict, dict, list]:
    from src.data.preprocessor import _clean_text, _whitespace_normalize

    body_clean = _clean_text(body)[:5000]
    subject_clean = _clean_text(subject)
    text_combined = _whitespace_normalize(f"{subject_clean} {body_clean}".strip())
    urls = _extract_urls(body)
    sender_domain = _extract_email_domain(sender)

    row = {
        "subject": subject,
        "body": body,
        "text_combined": text_combined,
        "sender": sender,
        "sender_domain": sender_domain,
        "reply_to": reply_to,
        "urls": urls,
        "url_count": len(urls),
    }
    rule_feats = extract_rule_features(row)
    row.update(rule_feats)
    return row, rule_feats, urls


def predict_and_explain(subject: str, body: str, sender: str, reply_to: str, model, extractor, threshold: float = 0.5) -> dict:
    row, rule_feats, urls = build_input_row(subject, body, sender, reply_to)
    reasons = generate_rule_explanation(rule_feats)

    if model is not None and extractor is not None:
        temp_df = pd.DataFrame([row])
        X = extractor.transform(temp_df)
        prob = float(model.predict_proba(X)[0][1])
        label = int(prob >= threshold)
        mode = "ML+Rule"
    else:
        risk = float(rule_feats.get("rule_risk_score", 0))
        prob = min(risk / 10.0, 0.99)
        label = int(prob >= threshold)
        mode = "Rule-only"

    return {
        "label": label,
        "confidence": prob,
        "reasons": reasons,
        "rule_features": rule_feats,
        "urls": urls,
        "mode": mode,
    }


SAMPLE_EMAILS = {
    "✅ 정상 이메일 (회의 안내)": {
        "sender": "manager@company.com",
        "reply_to": "manager@company.com",
        "subject": "Weekly Team Meeting - Thursday 3PM",
        "body": "Hi everyone,\n\nJust a reminder that our weekly team meeting is scheduled for Thursday at 3:00 PM in Conference Room B.\n\nPlease bring your project status updates.\n\nBest regards,\nSarah",
    },
    "🚨 피싱 이메일 (PayPal 사칭)": {
        "sender": "security@paypal-verify.tk",
        "reply_to": "noreply@paypal-support.ga",
        "subject": "URGENT: Your PayPal Account Has Been Suspended!",
        "body": "Dear PayPal Customer,\n\nYour account has been suspended due to suspicious activity. You must IMMEDIATELY verify your account to avoid permanent suspension.\n\nClick here to verify: http://paypal-secure.malicious.tk/login\n\nEnter your password, credit card number and social security number to confirm your identity.\n\nThis is your FINAL NOTICE. Act now before your account is terminated!",
    },
    "🚨 사기 이메일 (나이지리아 계열)": {
        "sender": "dr.johnson@freemail.ga",
        "reply_to": "urgent.transfer@yahoo.com",
        "subject": "CONFIDENTIAL BUSINESS PROPOSAL - $10.5 MILLION USD",
        "body": "Dear Friend,\n\nI am Dr. Johnson Williams, senior attorney. I write to solicit your assistance in a transaction involving transfer of $10.5 million USD. My client died intestate and I need your bank account details for the wire transfer.\n\nYou will receive 30% as your share. This is 100% risk free. Please reply with your bank account number and personal details to proceed with this unclaimed funds transaction.\n\nRegards,\nDr. Johnson Williams",
    },
    "🚨 협박 이메일 (랜섬웨어)": {
        "sender": "hacker@protonmail.com",
        "reply_to": "",
        "subject": "We have hacked your device",
        "body": "I have hacked your device and recorded you. I have your files and browsing history. Send $500 in Bitcoin to this address within 48 hours or I will expose everything to your contacts. This is not a joke. Legal action will follow if you ignore this. You have been warned.",
    },
}


def main():
    inject_custom_css()
    config = load_config()
    threshold = float(config.get("evaluation", {}).get("threshold", 0.5))
    app_cfg = config.get("app", {})
    selected_model_name = str(app_cfg.get("model_to_use", "xgboost"))
    model, extractor = load_artifacts(selected_model_name)

    st.markdown(
        f"""
        <div class="hero-box">
            <div style="font-size:0.9rem;font-weight:700;color:#4f6a5c;letter-spacing:0.04em;">PHISHING DETECTION STUDIO</div>
            <h1 style="margin:0.1rem 0 0.45rem 0;">{app_cfg.get('title', '메일 위협 분석 대시보드')}</h1>
            <p class="small-note" style="margin:0;">
                메일 본문과 헤더를 입력하거나 <b>.eml 파일</b>을 업로드하면, 분석 결과와 위험 신호를 함께 제공합니다.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.header("분석 옵션")
        uploaded_eml = st.file_uploader("eml 파일 업로드", type=["eml"], help="원본 메일 파일을 업로드하면 필드를 자동으로 채웁니다.")
        use_sample = st.selectbox("샘플 이메일 불러오기", options=["직접 입력"] + list(SAMPLE_EMAILS.keys()))

        st.divider()
        st.markdown("**모델 상태**")
        if model is not None and extractor is not None:
            st.markdown('<span class="status-pill status-ok">모델 로드 완료</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="status-pill status-warn">룰 기반 모드 실행 중</span>', unsafe_allow_html=True)
            st.caption("선택된 모델 또는 feature extractor 파일이 없어서 규칙 기반 분석으로 동작합니다.")

        st.divider()
        st.markdown(
            f"**프로젝트**: 피싱 이메일 탐지 AI  \n"
            f"**선택 모델**: {selected_model_name}  \n"
            f"**설명 방식**: Rule Explainer + Feature 분석"
        )

    st.subheader("이메일 입력")
    eml_data = parse_uploaded_eml(uploaded_eml)

    if uploaded_eml is not None:
        default_sender = eml_data["sender"]
        default_reply = eml_data["reply_to"]
        default_subject = eml_data["subject"]
        default_body = eml_data["body"]
    elif use_sample != "직접 입력":
        sample = SAMPLE_EMAILS[use_sample]
        default_sender = sample["sender"]
        default_reply = sample["reply_to"]
        default_subject = sample["subject"]
        default_body = sample["body"]
    else:
        default_sender = default_reply = default_subject = default_body = ""

    col1, col2 = st.columns(2)
    with col1:
        sender = st.text_input("발신자 (From)", value=default_sender, placeholder="sender@example.com")
    with col2:
        reply_to = st.text_input("Reply-To", value=default_reply, placeholder="reply@example.com")

    subject = st.text_input("제목 (Subject)", value=default_subject, placeholder="이메일 제목")
    body = st.text_area("본문 (Body)", value=default_body, height=200, placeholder="이메일 본문 내용...")
    analyze_btn = st.button("🔍 분석하기", type="primary", use_container_width=True)

    if analyze_btn:
        if not subject.strip() and not body.strip():
            st.error("제목 또는 본문을 입력해주세요.")
            return

        with st.spinner("분석 중..."):
            result = predict_and_explain(subject, body, sender, reply_to, model, extractor, threshold=threshold)

        label = result["label"]
        prob = result["confidence"]
        reasons = result["reasons"]
        rule_feats = result["rule_features"]
        urls = result["urls"]

        st.divider()

        col_result, col_conf = st.columns([3, 1])
        with col_result:
            if label == 1:
                st.error("## 피싱/위협 이메일로 판정")
            else:
                st.success("## 정상 이메일로 판정")
        with col_conf:
            risk_score = min(max(prob, 0.0), 1.0)
            st.metric("위험 점수", f"{round(risk_score * 100, 1)}%")
            st.progress(risk_score)
            if label == 1:
                st.caption("값이 높을수록 위협 메일일 가능성이 높습니다.")
            else:
                st.caption("정상으로 판정되었지만, 낮은 수준의 위험 신호가 일부 포함될 수 있습니다.")

        tab1, tab2, tab3 = st.tabs(["판단 근거", "링크 분석", "피처 상세"])

        with tab1:
            if reasons:
                st.markdown("### 감지된 위험 신호")
                for r in reasons:
                    st.markdown(f'<div class="risk-panel risk-{r["severity"]}">{r["text"]}</div>', unsafe_allow_html=True)
            else:
                if label == 1:
                    st.info("모델이 학습 패턴을 기반으로 위협을 탐지하였습니다. (명시적 룰 미매칭)")
                else:
                    st.success("명확한 피싱/사기 패턴이 감지되지 않았습니다.")

            brand = rule_feats.get("impersonated_brand", "")
            if brand:
                st.warning(f"**사칭 의심 브랜드**: {brand.upper()}")

        with tab2:
            st.markdown(f"**발견된 URL**: {len(urls)}개")
            if urls:
                for url in urls[:10]:
                    is_suspicious = any(url.lower().endswith(tld) or f"{tld}/" in url.lower() for tld in SUSPICIOUS_TLDS)
                    if is_suspicious:
                        st.error(url)
                    else:
                        st.info(url)
                if len(urls) > 10:
                    st.caption(f"... 외 {len(urls) - 10}개")
            else:
                st.info("URL이 감지되지 않았습니다.")

        with tab3:
            feat_display = {
                "사칭 점수": rule_feats.get("impersonation_score", 0),
                "긴급 유도 점수": rule_feats.get("urgency_score", 0),
                "개인정보 요구": rule_feats.get("credential_request", 0),
                "금전 요구": rule_feats.get("money_request", 0),
                "협박/공포 문구": rule_feats.get("threat_language", 0),
                "수상한 URL": rule_feats.get("has_suspicious_url", 0),
                "URL 도메인 불일치": rule_feats.get("url_domain_mismatch", 0),
                "HTTP(비암호화) URL": rule_feats.get("has_http_url", 0),
                "전체 위험 점수 (0~10)": rule_feats.get("rule_risk_score", 0),
            }
            st.dataframe(pd.DataFrame(list(feat_display.items()), columns=["피처", "값"]), use_container_width=True, hide_index=True)

        if model is None:
            st.info("노트: 현재 룰 기반 분석만 실행 중입니다. 선택한 ML 모델 파일을 준비하면 더 정확한 판별이 가능합니다.")


if __name__ == "__main__":
    main()
