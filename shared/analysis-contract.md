# Analysis Contract

## 1. Analyze Request

```json
{
  "provider": "gmail",
  "sender": "security@example.com",
  "sender_name": "Google Security",
  "reply_to": "reply@example.com",
  "subject": "Urgent notice",
  "body": "mail body text",
  "body_snippet": "mail body text",
  "links": [
    {
      "href": "http://example.tk/login",
      "text": "Verify now"
    }
  ],
  "attachments": ["invoice.zip"],
  "source_url": "https://mail.google.com/mail/u/0/#inbox/...",
  "coverage": {
    "messageCount": 1,
    "textLength": 1240,
    "linkCount": 1,
    "attachmentCount": 1
  }
}
```

### 필드 의미
- `provider`: 메일 공급자 (`gmail`, `outlook` 등)
- `sender`: From 주소 또는 발신자 문자열
- `sender_name`: 표시 이름
- `reply_to`: Reply-To 주소
- `subject`: 메일 제목
- `body`: 메일 본문 전체 또는 가능한 최대 본문
- `body_snippet`: 확장이 확보한 요약 본문
- `links`: DOM에서 수집한 링크 목록
- `attachments`: 첨부 파일명 목록
- `source_url`: 메일이 열린 웹 URL
- `coverage`: 확장이 실제로 어느 정도 수집했는지에 대한 메타데이터

## 2. Analyze Response

```json
{
  "label": 1,
  "verdict": "phishing",
  "score": 92.4,
  "confidence": 0.924,
  "level": "high-risk",
  "reasons": [
    "비밀번호/개인정보 입력 요청 표현이 감지되었습니다."
  ],
  "rule_features": {
    "urgency_score": 3,
    "credential_request": 1,
    "has_suspicious_url": 1,
    "rule_risk_score": 9
  },
  "urls": ["http://example.tk/login"],
  "attachment_count": 1,
  "provider": "gmail",
  "mode": "ml-api",
  "model": "xgboost"
}
```

### 응답 의미
- `label`: 이진 판정값 (`1` = 피싱, `0` = 정상)
- `verdict`: 사람이 읽기 쉬운 판정 (`phishing`, `legit`)
- `score`: 0~100 위험 점수
- `confidence`: 0~1 확률값
- `level`: UI 경고 레벨
- `reasons`: 사용자에게 보여줄 설명 목록
- `rule_features`: 디버그/설명용 세부 피처
- `urls`: 실제 분석에 사용된 링크 목록
- `attachment_count`: 분석 시 반영된 첨부 개수
- `provider`: 분석 대상 메일 서비스
- `mode`: `ml-api`, `rule-api`, 또는 확장 내부 최소 안전망인 `rule-fallback`
- `model`: 사용된 모델명

## 3. 레벨 기준
- `safe`
- `caution`
- `suspicious`
- `high-risk`

## 4. 통합 원칙
- 확장은 이 계약만 믿고 결과를 표시한다.
- 분석 서비스는 내부 모델/룰 변경이 있어도 응답 구조는 최대한 안정적으로 유지한다.
- fallback rule engine은 가능하면 이 응답 구조를 흉내 내도록 유지한다.
- 확장은 실시간 수집기, 분석 서비스는 학습 모델 기반 판단기로 역할을 분리한다.
