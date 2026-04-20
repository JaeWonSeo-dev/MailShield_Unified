"""
로컬 ML 분석 API

실행:
    python app/ml_api.py

기본 주소:
    http://127.0.0.1:8765/analyze
    http://127.0.0.1:8765/health
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

import joblib
import pandas as pd
import yaml

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from src.data.preprocessor import _clean_text, _extract_email_domain, _extract_urls, _whitespace_normalize
from src.explainability.rule_explainer import generate_rule_explanation
from src.features.rule_features import extract_rule_features

HOST = "127.0.0.1"
PORT = 8765


def load_config():
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


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


CONFIG = load_config()
MODEL_NAME = str(CONFIG.get("app", {}).get("model_to_use", "xgboost"))
THRESHOLD = float(CONFIG.get("evaluation", {}).get("threshold", 0.5))
MODEL, EXTRACTOR = load_artifacts(MODEL_NAME)
ACTIVE_MODEL_NAME = MODEL_NAME if MODEL is not None and EXTRACTOR is not None else "rule-only"


def _normalize_link_items(raw_links: Any) -> List[Dict[str, str]]:
    normalized: List[Dict[str, str]] = []
    for item in raw_links or []:
        if isinstance(item, dict):
            href = str(item.get("href", "") or "").strip()
            text = str(item.get("text", "") or "").strip()
        else:
            href = str(item or "").strip()
            text = ""
        if href:
            normalized.append({"href": href, "text": text})
    return normalized


def _normalize_string_list(values: Any) -> List[str]:
    output: List[str] = []
    for value in values or []:
        text = str(value or "").strip()
        if text:
            output.append(text)
    return output


def _extract_sender_email(sender: str, sender_name: str = "") -> str:
    candidates = [sender, sender_name]
    for candidate in candidates:
        text = str(candidate or "")
        if "@" in text:
            return text
    return str(sender or "")


def build_input_row(payload: Dict[str, Any]):
    subject = str(payload.get("subject", "") or "")
    body = str(payload.get("body", "") or "")
    sender = str(payload.get("sender", "") or "")
    sender_name = str(payload.get("sender_name", "") or "")
    reply_to = str(payload.get("reply_to", "") or "")
    provider = str(payload.get("provider", "") or "")
    source_url = str(payload.get("source_url", "") or "")
    body_snippet = str(payload.get("body_snippet", "") or "")
    coverage = payload.get("coverage", {}) or {}

    links = _normalize_link_items(payload.get("links"))
    attachments = _normalize_string_list(payload.get("attachments"))

    fallback_body_parts = [body, body_snippet]
    if links:
        fallback_body_parts.append("\n".join(link["href"] for link in links))
    if attachments:
        fallback_body_parts.append("\n".join(attachments))

    body_effective = next((part for part in fallback_body_parts if str(part).strip()), "")
    body_clean = _clean_text(body_effective)[:5000]
    subject_clean = _clean_text(subject)
    text_combined = _whitespace_normalize(f"{subject_clean} {body_clean}".strip())

    extracted_urls = [link["href"] for link in links] or _extract_urls(body_effective)
    sender_email = _extract_sender_email(sender, sender_name)
    sender_domain = _extract_email_domain(sender_email)

    row = {
        "subject": subject,
        "body": body_effective,
        "text_combined": text_combined,
        "sender": sender_email,
        "sender_name": sender_name,
        "sender_domain": sender_domain,
        "reply_to": reply_to,
        "urls": extracted_urls,
        "url_count": len(extracted_urls),
        "provider": provider,
        "source_url": source_url,
        "attachments": attachments,
        "attachment_count": len(attachments),
        "body_snippet": body_snippet,
        "coverage": coverage,
    }
    rule_feats = extract_rule_features(row)
    row.update(rule_feats)
    return row, rule_feats, extracted_urls, attachments


def predict_email(payload: Dict[str, Any]):
    global MODEL, EXTRACTOR, ACTIVE_MODEL_NAME

    row, rule_feats, urls, attachments = build_input_row(payload)
    reasons = generate_rule_explanation(rule_feats)

    if MODEL is not None and EXTRACTOR is not None:
        temp_df = pd.DataFrame([row])
        X = EXTRACTOR.transform(temp_df)

        try:
            prob = float(MODEL.predict_proba(X)[0][1])
        except Exception:
            fallback_model, fallback_extractor = load_artifacts("lr")
            if fallback_model is not None and fallback_extractor is not None:
                try:
                    MODEL, EXTRACTOR = fallback_model, fallback_extractor
                    ACTIVE_MODEL_NAME = "lr"
                    X = EXTRACTOR.transform(temp_df)
                    prob = float(MODEL.predict_proba(X)[0][1])
                except Exception:
                    risk = float(rule_feats.get("rule_risk_score", 0))
                    prob = min(risk / 10.0, 0.99)
                    ACTIVE_MODEL_NAME = "rule-only"
            else:
                risk = float(rule_feats.get("rule_risk_score", 0))
                prob = min(risk / 10.0, 0.99)
                ACTIVE_MODEL_NAME = "rule-only"
    else:
        risk = float(rule_feats.get("rule_risk_score", 0))
        prob = min(risk / 10.0, 0.99)
        ACTIVE_MODEL_NAME = "rule-only"

    level = "high-risk" if prob >= 0.75 else "suspicious" if prob >= 0.5 else "caution" if prob >= 0.25 else "safe"
    verdict = "phishing" if prob >= THRESHOLD else "legit"

    return {
        "label": int(prob >= THRESHOLD),
        "verdict": verdict,
        "score": round(prob * 100, 1),
        "confidence": prob,
        "level": level,
        "reasons": [r["text"] for r in reasons],
        "rule_features": rule_feats,
        "urls": urls,
        "attachment_count": len(attachments),
        "provider": row.get("provider", ""),
        "mode": "ml-api" if ACTIVE_MODEL_NAME != "rule-only" else "rule-api",
        "model": ACTIVE_MODEL_NAME,
    }


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_json(200, {"ok": True})

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {
                "ok": True,
                "ready": True,
                "model": ACTIVE_MODEL_NAME,
                "threshold": THRESHOLD,
                "mode": "ml-api" if ACTIVE_MODEL_NAME != "rule-only" else "rule-api",
            })
            return

        self._send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/analyze":
            self._send_json(404, {"error": "not_found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8")) if raw else {}
            result = predict_email(data)
            self._send_json(200, result)
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"ML API listening on http://{HOST}:{PORT}/analyze")
    print(f"Health check available at http://{HOST}:{PORT}/health")
    server.serve_forever()
