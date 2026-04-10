# Analysis Contract

## 1. Analyze Request

```json
{
  "sender": "security@example.com",
  "reply_to": "reply@example.com",
  "subject": "Urgent notice",
  "body": "mail body text"
}
```

### 필드 의미
- `sender`: From 주소 또는 발신자 문자열
- `reply_to`: Reply-To 주소
- `subject`: 메일 제목
- `body`: 메일 본문 전체 또는 가능한 최대 본문

## 2. Analyze Response

```json
{
  "label": 1,
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
  "mode": "ml-api",
  "model": "xgboost"
}
```

## 3. 레벨 기준
- `safe`
- `caution`
- `suspicious`
- `high-risk`

## 4. 통합 원칙
- 확장은 이 계약만 믿고 결과를 표시한다.
- 분석 서비스는 내부 모델/룰 변경이 있어도 응답 구조는 최대한 안정적으로 유지한다.
- fallback rule engine은 가능하면 이 응답 구조를 흉내 내도록 유지한다.
