"""
학습 데이터 증강 모듈

목표:
  - 링크 유도형 피싱 (직접 개인정보 요구 없이 클릭 유도)
  - 악성코드 다운로드/설치 유도형 피싱
패턴의 학습 비중을 높여 일반화 성능을 보완한다.
"""

from __future__ import annotations

from typing import Dict, Any
import numpy as np
import pandas as pd


LINK_LURE_TEMPLATES = [
    "Please review the shared document here: {url}",
    "Invoice review required. Open this portal now: {url}",
    "Payment discrepancy detected. Check details at {url}",
    "문서 확인 요청: 아래 링크에서 검토해 주세요 {url}",
    "외부 협업 포털 접속 후 승인 처리 바랍니다: {url}",
]

MALWARE_LURE_TEMPLATES = [
    "Security update required. Download and run: {url}",
    "To access protected file, install viewer from {url}",
    "업무 파일 열람을 위해 보안 업데이트를 설치하세요: {url}",
    "매크로 활성화 후 파일을 실행해 주세요: {url}",
]

SYNTHETIC_URLS = [
    "https://secure-verify-portal.co/docs/review",
    "https://account-protection-center.com/session/validate",
    "http://invoice-approval-center.net/open/document",
    "https://doc-shared-access.co/workspace/view",
    "https://update-center-cloud.com/installer/security_patch.zip",
]


def augment_training_data(
    train_df: pd.DataFrame,
    config: Dict[str, Any] | None = None,
) -> pd.DataFrame:
    """
    위협(label=1) 샘플 일부를 텍스트 변형해 증강본을 생성한다.

    Args:
        train_df: 원본 학습 데이터
        config: augmentation 설정(dict)
            - enabled: bool
            - threat_sample_ratio: float (0~1)
            - variants_per_sample: int
            - random_seed: int

    Returns:
        증강 포함 학습 데이터프레임
    """
    aug_cfg = config or {}
    if not aug_cfg.get("enabled", False):
        return train_df

    ratio = float(aug_cfg.get("threat_sample_ratio", 0.3))
    variants_per_sample = int(aug_cfg.get("variants_per_sample", 1))
    seed = int(aug_cfg.get("random_seed", 42))

    if ratio <= 0 or variants_per_sample <= 0:
        return train_df

    df = train_df.copy()
    threat_df = df[df["label"] == 1]
    if threat_df.empty:
        return df

    rng = np.random.default_rng(seed)
    sample_n = max(1, int(len(threat_df) * min(ratio, 1.0)))
    sampled_idx = rng.choice(threat_df.index.values, size=sample_n, replace=False)
    sampled = threat_df.loc[sampled_idx]

    synthetic_rows = []
    synth_id = 0

    for _, row in sampled.iterrows():
        for _ in range(variants_per_sample):
            synth_id += 1
            url = rng.choice(SYNTHETIC_URLS).item()
            use_malware = bool(rng.integers(0, 2))

            if use_malware:
                injected = rng.choice(MALWARE_LURE_TEMPLATES).item().format(url=url)
            else:
                injected = rng.choice(LINK_LURE_TEMPLATES).item().format(url=url)

            subject = str(row.get("subject", "") or "")
            body = str(row.get("body", "") or "")

            new_subject = subject if subject else ("Urgent document action" if not use_malware else "Security update notice")
            new_body = f"{body}\n\n{injected}".strip()

            new_row = row.copy()
            new_row["subject"] = new_subject
            new_row["body"] = new_body
            new_row["text_combined"] = f"{new_subject} {new_body}".strip()
            new_row["source"] = f"{row.get('source', 'dataset')}_aug"
            new_row["email_id"] = f"{row.get('email_id', 'email')}_aug_{synth_id:05d}"

            synthetic_rows.append(new_row)

    if not synthetic_rows:
        return df

    aug_df = pd.DataFrame(synthetic_rows)
    out = pd.concat([df, aug_df], ignore_index=True)
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)
