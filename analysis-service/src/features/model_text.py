"""
Model text composition helpers.

The classifier should learn from observed mail fields instead of receiving
hand-authored risk scores.  These helpers convert raw mail metadata into text
tokens that TF-IDF based models can learn from directly.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Iterable, Mapping

import pandas as pd


_WHITESPACE_PATTERN = re.compile(r"\s+")


def build_model_text_record(row: Mapping[str, Any]) -> str:
    parts = [
        _clean_piece(row.get("subject_clean") or row.get("subject")),
        _clean_piece(row.get("body_clean") or row.get("body")),
        _field_token("sender", row.get("sender")),
        _field_token("sender_domain", row.get("sender_domain")),
        _field_token("reply_to", row.get("reply_to")),
        _field_token("reply_to_domain", row.get("reply_to_domain")),
        *_list_tokens("url", row.get("urls") or row.get("urls_raw")),
        *_list_tokens("attachment", row.get("attachments")),
    ]
    return _normalize(" ".join(part for part in parts if part))


def build_model_text_dataframe(df: pd.DataFrame) -> pd.Series:
    return df.apply(build_model_text_record, axis=1)


def _field_token(name: str, value: Any) -> str:
    cleaned = _clean_piece(value)
    return f"{name}={cleaned}" if cleaned else ""


def _list_tokens(name: str, values: Any) -> Iterable[str]:
    for value in _coerce_list(values):
        cleaned = _clean_piece(value)
        if cleaned:
            yield f"{name}={cleaned}"


def _coerce_list(values: Any) -> list:
    if values is None:
        return []
    if isinstance(values, list):
        return values
    if isinstance(values, tuple) or isinstance(values, set):
        return list(values)
    if isinstance(values, str):
        text = values.strip()
        if not text:
            return []
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = ast.literal_eval(text)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass
        return re.split(r"[\s,]+", text)
    return [values]


def _clean_piece(value: Any) -> str:
    if value is None:
        return ""
    return _normalize(str(value))


def _normalize(text: str) -> str:
    return _WHITESPACE_PATTERN.sub(" ", text).strip()
