# MailShield Unified

MailShield Unified는 Gmail과 Outlook Web에서 열람 중인 메일을 수집해 정상 메일, 스팸 메일, 피싱 메일을 실시간으로 분류하는 Chrome Extension 기반 메일 보안 프로젝트입니다.

확장 프로그램은 사용자가 메일을 열었을 때 제목, 발신자, Reply-To, 본문, 링크, 첨부 정보를 브라우저 화면에서 추출하고, 로컬 분석 API는 학습된 머신러닝 모델로 세 클래스 확률과 피싱 점수를 반환합니다. 스팸은 피싱과 분리해 판단하며, 피싱으로 분류될 때만 피싱 강도와 근거를 강조합니다.

## Features

- Gmail, Outlook Web 메일 열람 화면 자동 감지
- 제목, 발신자, Reply-To, 본문, 링크, 첨부명 수집
- 로컬 ML API 기반 정상/스팸/피싱 3-class 분류
- 피싱 점수, 스팸 점수, confidence, 판정 근거, 수집 범위 오버레이 표시
- 정상은 초록색, 스팸은 중립색, 피싱은 강도에 따라 노랑/주황/빨강으로 표시
- API 장애 시 확장 내부 rule fallback 엔진으로 기본 분석 유지
- 공개 피싱/스팸/정상 메일 데이터셋 다운로드 및 재학습 지원
- 룰 점수에 의존하지 않는 text-only 학습 파이프라인
- content group split 기반 train/validation/test 누수 방지

## Architecture

```text
MailShield_Unified/
├─ extension/                 # Chrome Extension
│  ├─ manifest.json
│  ├─ popup.html
│  ├─ popup.js
│  └─ src/
│     ├─ content.js           # Gmail/Outlook DOM 수집 및 오버레이 렌더링
│     ├─ background.js        # ML API 호출 및 fallback 처리
│     ├─ risk-engine.js       # API 장애 시 사용하는 로컬 fallback 엔진
│     └─ overlay.css
├─ analysis-service/          # ML 학습/추론 서비스
│  ├─ app/ml_api.py           # Chrome Extension이 호출하는 로컬 HTTP API
│  ├─ src/data/               # 데이터 로딩/전처리
│  ├─ src/features/           # TF-IDF, feature selection, 모델 입력 구성
│  ├─ src/models/             # 학습 및 평가
│  ├─ scripts/                # 데이터셋 다운로드/학습 스크립트
│  ├─ models/saved/           # 학습된 모델과 feature extractor
│  └─ reports/                # 평가 결과
├─ docs/
└─ shared/
```

## Detection Pipeline

1. 사용자가 Gmail 또는 Outlook Web에서 메일을 엽니다.
2. Chrome Extension content script가 메일 DOM에서 분석 문맥을 수집합니다.
3. background service worker가 `http://127.0.0.1:8765/analyze`로 분석 요청을 보냅니다.
4. ML API가 학습된 모델과 feature extractor로 정상/스팸/피싱 확률을 계산합니다.
5. 확장 프로그램이 판정, 피싱 점수, 스팸 점수, confidence, 주요 근거를 오버레이로 표시합니다.

## Model

현재 기본 운영 모델은 `LogisticRegressionCV` 기반 3-class 분류기입니다. Chrome Extension에서 점수화가 필요하므로 확률 출력이 안정적이고 추론 속도가 빠른 모델을 우선 선택했습니다.

학습 입력은 사람이 작성한 룰 점수가 아니라 메일에서 관찰된 필드입니다.

- `subject`
- `body`
- `sender`
- `sender_domain`
- `reply_to`
- `reply_to_domain`
- `urls`
- `attachments`

Feature selection은 `Chi-square SelectKBest`를 사용합니다.

현재 설정:

- TF-IDF max features: `50000`
- Feature selection: `chi2`, `k=30000`
- Rule numeric features: disabled
- Data augmentation: disabled
- Classification mode: `ham`, `spam`, `phishing`
- Decision rule: 세 클래스 확률 중 argmax
- Phishing severity: 낮음/중간/높음 색상 단계

## Dataset

공개 데이터셋을 프로젝트 안으로 다운로드해 통합 학습합니다.

사용 원천:

- [rokibulroni/Phishing-Email-Dataset](https://github.com/rokibulroni/Phishing-Email-Dataset)
- [zefang-liu/phishing-email-dataset](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset)
- [locuoco/the-biggest-spam-ham-phish-email-dataset-300000](https://huggingface.co/datasets/locuoco/the-biggest-spam-ham-phish-email-dataset-300000)

최근 학습 데이터 규모:

| Step | Count |
| --- | ---: |
| Raw rows before dedupe | 466,584 |
| Rows after dedupe | 379,397 |
| Rows after preprocessing | 378,899 |
| Train | 264,849 |
| Validation | 57,320 |
| Test | 56,730 |

Train label distribution:

| Class | Count |
| --- | ---: |
| Ham | 124,697 |
| Spam | 102,101 |
| Phishing | 35,716 |
| Fraud mapped to phishing | 2,335 |

최근 평가 결과:

| Metric | Score |
| --- | ---: |
| Accuracy | 0.9359 |
| Macro F1 | 0.9110 |
| Weighted F1 | 0.9364 |
| Macro Precision | 0.9057 |
| Macro Recall | 0.9169 |
| ROC-AUC OVR | 0.9883 |

Class-level test result:

| Class | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| Ham | 0.99 | 0.98 | 0.98 |
| Spam | 0.93 | 0.91 | 0.92 |
| Phishing | 0.81 | 0.86 | 0.83 |

평가는 content group split을 사용해 같은 정규화 메일 본문이 train, validation, test에 동시에 들어가지 않도록 구성합니다. 이 방식은 랜덤 split보다 점수가 낮아질 수 있지만, 실제 신규 메일에 대한 일반화 성능을 더 보수적으로 추정합니다.

## Requirements

- Chrome 또는 Microsoft Edge
- Python 3.9+
- Node.js 18+

macOS에서 XGBoost를 사용하려면 OpenMP 런타임이 필요할 수 있습니다.

```bash
brew install libomp
```

현재 운영 기본값은 `lr`입니다. XGBoost는 macOS OpenMP 환경에 따라 로드가 실패할 수 있어 선택 모델로만 남겨두었습니다.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r analysis-service/requirements.txt
```

## Run Analysis API

```bash
. .venv/bin/activate
python analysis-service/app/ml_api.py
```

기본 엔드포인트:

- `http://127.0.0.1:8765/health`
- `http://127.0.0.1:8765/analyze`

Health check:

```bash
curl -s http://127.0.0.1:8765/health
```

## Load Extension

1. Chrome 또는 Edge에서 `chrome://extensions`를 엽니다.
2. Developer mode를 켭니다.
3. Load unpacked를 선택합니다.
4. `extension/` 폴더를 선택합니다.
5. 확장 팝업에서 API URL이 `http://127.0.0.1:8765/analyze`인지 확인합니다.
6. Gmail 또는 Outlook Web에서 메일을 열어 분석 오버레이를 확인합니다.

지원 대상:

- `https://mail.google.com/*`
- `https://outlook.live.com/*`
- `https://outlook.office.com/*`
- `https://outlook.office365.com/*`

## Training

공개 데이터셋 다운로드:

```bash
. .venv/bin/activate
python analysis-service/scripts/download_open_datasets.py
```

전처리:

```bash
. .venv/bin/activate
cd analysis-service
python src/data/preprocessor.py
```

학습:

```bash
. .venv/bin/activate
cd analysis-service
python src/models/baseline.py
```

학습 결과는 다음 위치에 저장됩니다.

- `analysis-service/models/saved/lr_model.pkl`
- `analysis-service/models/saved/feature_extractor.pkl`
- `analysis-service/models/saved/model_metadata.json`
- `analysis-service/reports/training_summary.json`
- `analysis-service/results/latest-summary.md`

## Test

```bash
node extension/tests/smoke.mjs
. .venv/bin/activate
python -m unittest analysis-service/tests/test_smoke.py
```

## API Contract

Example request:

```json
{
  "provider": "gmail",
  "sender": "security@example.com",
  "sender_name": "Security Team",
  "reply_to": "support@example.net",
  "subject": "Urgent: verify your account",
  "body": "Please verify your password using the secure link below.",
  "links": [
    {
      "href": "http://example-login.test/verify",
      "text": "Verify now"
    }
  ],
  "attachments": []
}
```

Example response:

```json
{
  "label": 1,
  "verdict": "phishing",
  "classification": "phishing",
  "score": 92.4,
  "phishing_score": 92.4,
  "spam_score": 7.5,
  "confidence": 0.924,
  "level": "phishing-high",
  "class_probabilities": {
    "ham": 0.1,
    "spam": 7.5,
    "phishing": 92.4
  },
  "mode": "ml-api",
  "model": "lr",
  "reasons": [
    "비밀번호/개인정보 입력 요청 표현이 감지되었습니다."
  ]
}
```

## Notes

- 분석 API는 기본적으로 로컬에서 실행됩니다.
- 메일 내용은 외부 서버로 전송되지 않고 로컬 API에서 분석됩니다.
- `reasons`와 `rule_features`는 설명 및 fallback 용도이며, 기본 학습 모델 입력에는 rule numeric feature가 포함되지 않습니다.
- 공개 데이터셋 기준 성능은 실제 조직/개인 메일함 성능과 다를 수 있으므로 실제 메일 샘플 기반 검증이 필요합니다.
