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

from src.data.preprocessor import _clean_text, _extract_email_domain, _extract_urls
from src.explainability.rule_explainer import generate_rule_explanation
from src.features.model_text import build_model_text_record
from src.features.rule_features import extract_rule_features

HOST = "127.0.0.1"
PORT = 8765


def load_config():
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_model_metadata():
    metadata_path = ROOT / "models" / "saved" / "model_metadata.json"
    if not metadata_path.exists():
        return {}
    try:
        with open(metadata_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        print(f"[MailShield] failed to load model metadata: {exc}", file=sys.stderr)
        return {}


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

    try:
        model = joblib.load(model_path)
        extractor = joblib.load(extractor_path)
        _patch_model_compatibility(model)
        return model, extractor
    except Exception as exc:
        message = next((line.strip() for line in str(exc).splitlines() if line.strip()), exc.__class__.__name__)
        print(f"[MailShield] failed to load {model_name} artifacts; falling back. reason={message}", file=sys.stderr)
        return None, None


def _patch_model_compatibility(model):
    if model.__class__.__name__ == "LogisticRegressionCV" and not hasattr(model, "multi_class"):
        model.multi_class = "auto"


def load_preferred_artifacts(preferred_model_name: str):
    candidates = [preferred_model_name, "lr", "xgboost"]
    seen = set()

    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)

        model, extractor = load_artifacts(candidate)
        if model is not None and extractor is not None:
            return candidate, model, extractor

    return "rule-only", None, None


CONFIG = load_config()
MODEL_METADATA = load_model_metadata()
MODEL_NAME = str(CONFIG.get("app", {}).get("model_to_use", "xgboost"))
ACTIVE_MODEL_NAME, MODEL, EXTRACTOR = load_preferred_artifacts(MODEL_NAME)
THRESHOLD = float(
    MODEL_METADATA.get("models", {})
    .get(ACTIVE_MODEL_NAME, {})
    .get("threshold", CONFIG.get("evaluation", {}).get("threshold", 0.5))
)
CLASS_NAMES = MODEL_METADATA.get("class_names", ["ham", "spam", "phishing"])
CLASS_LABELS = MODEL_METADATA.get("class_labels", {"ham": 0, "spam": 1, "phishing": 2})
SEVERITY_THRESHOLDS = MODEL_METADATA.get("phishing_severity_thresholds", {"low": 0.4, "medium": 0.65, "high": 0.85})


def _level_for_class(verdict: str, phishing_prob: float) -> str:
    if verdict == "phishing":
        if phishing_prob >= float(SEVERITY_THRESHOLDS.get("high", 0.85)):
            return "phishing-high"
        if phishing_prob >= float(SEVERITY_THRESHOLDS.get("medium", 0.65)):
            return "phishing-medium"
        return "phishing-low"
    if verdict == "spam":
        return "spam"
    return "safe"


def _legacy_level(prob: float) -> str:
    if prob >= 0.75:
        return "phishing-high"
    if prob >= 0.5:
        return "phishing-medium"
    if prob >= 0.25:
        return "phishing-low"
    return "safe"


def _rule_prediction(prob: float) -> Dict[str, Any]:
    verdict = "phishing" if prob >= THRESHOLD else "legit"
    return {
        "label": int(prob >= THRESHOLD),
        "verdict": verdict,
        "classification": verdict,
        "score": round(prob * 100, 1),
        "phishing_score": round(prob * 100, 1),
        "spam_score": 0.0,
        "confidence": prob,
        "level": _legacy_level(prob) if verdict == "phishing" else "safe",
        "class_probabilities": {"ham": round((1 - prob) * 100, 1), "spam": 0.0, "phishing": round(prob * 100, 1)},
    }


def _probability_result(model, X) -> Dict[str, Any]:
    probabilities = model.predict_proba(X)[0]
    model_classes = list(getattr(model, "classes_", range(len(probabilities))))

    if len(probabilities) <= 2:
        return _rule_prediction(float(probabilities[1]))

    prob_by_label = {int(label): float(probabilities[idx]) for idx, label in enumerate(model_classes)}
    class_probabilities = {
        "ham": prob_by_label.get(int(CLASS_LABELS.get("ham", 0)), 0.0),
        "spam": prob_by_label.get(int(CLASS_LABELS.get("spam", 1)), 0.0),
        "phishing": prob_by_label.get(int(CLASS_LABELS.get("phishing", 2)), 0.0),
    }
    predicted_label = int(model_classes[int(probabilities.argmax())])
    verdict = next((name for name, label in CLASS_LABELS.items() if int(label) == predicted_label), "legit")
    if verdict == "ham":
        verdict = "legit"

    phishing_prob = class_probabilities["phishing"]
    spam_prob = class_probabilities["spam"]
    confidence = max(class_probabilities.values())

    return {
        "label": predicted_label,
        "verdict": verdict,
        "classification": verdict,
        "score": round(phishing_prob * 100, 1),
        "phishing_score": round(phishing_prob * 100, 1),
        "spam_score": round(spam_prob * 100, 1),
        "confidence": confidence,
        "level": _level_for_class(verdict, phishing_prob),
        "class_probabilities": {name: round(value * 100, 1) for name, value in class_probabilities.items()},
    }


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
    extracted_urls = [link["href"] for link in links] or _extract_urls(body_effective)
    sender_email = _extract_sender_email(sender, sender_name)
    sender_domain = _extract_email_domain(sender_email)
    reply_to_domain = _extract_email_domain(reply_to)

    row = {
        "subject": subject,
        "body": body_effective,
        "subject_clean": subject_clean,
        "body_clean": body_clean,
        "sender": sender_email,
        "sender_name": sender_name,
        "sender_domain": sender_domain,
        "reply_to": reply_to,
        "reply_to_domain": reply_to_domain,
        "urls": extracted_urls,
        "url_count": len(extracted_urls),
        "provider": provider,
        "source_url": source_url,
        "attachments": attachments,
        "attachment_count": len(attachments),
        "body_snippet": body_snippet,
        "coverage": coverage,
    }
    row["text_combined"] = build_model_text_record(row)
    rule_feats = extract_rule_features(row)
    row.update(rule_feats)
    return row, rule_feats, extracted_urls, attachments


def predict_email(payload: Dict[str, Any]):
    global MODEL, EXTRACTOR, ACTIVE_MODEL_NAME

    row, rule_feats, urls, attachments = build_input_row(payload)
    reasons = generate_rule_explanation(rule_feats)
    prediction = None

    if MODEL is not None and EXTRACTOR is not None:
        temp_df = pd.DataFrame([row])
        X = EXTRACTOR.transform(temp_df)

        try:
            prediction = _probability_result(MODEL, X)
        except Exception:
            fallback_model, fallback_extractor = load_artifacts("lr")
            if fallback_model is not None and fallback_extractor is not None:
                try:
                    MODEL, EXTRACTOR = fallback_model, fallback_extractor
                    ACTIVE_MODEL_NAME = "lr"
                    X = EXTRACTOR.transform(temp_df)
                    prediction = _probability_result(MODEL, X)
                except Exception:
                    risk = float(rule_feats.get("rule_risk_score", 0))
                    prediction = _rule_prediction(min(risk / 10.0, 0.99))
                    ACTIVE_MODEL_NAME = "rule-only"
            else:
                risk = float(rule_feats.get("rule_risk_score", 0))
                prediction = _rule_prediction(min(risk / 10.0, 0.99))
                ACTIVE_MODEL_NAME = "rule-only"
    else:
        risk = float(rule_feats.get("rule_risk_score", 0))
        prediction = _rule_prediction(min(risk / 10.0, 0.99))
        ACTIVE_MODEL_NAME = "rule-only"

    if prediction["verdict"] == "spam":
        reasons = [{"text": "광고/홍보성 스팸 패턴에 더 가깝게 분류되었습니다. 피싱 점수는 별도로 낮게 유지됩니다."}]
    elif prediction["verdict"] == "legit":
        reasons = []

    return {
        **prediction,
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
                "classification_mode": MODEL_METADATA.get("classification_mode", "binary"),
                "class_names": CLASS_NAMES,
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
