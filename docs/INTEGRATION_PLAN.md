# Integration Plan

## 목표 아키텍처

```text
[Gmail / Outlook Web]
        ↓
[Browser Extension]
  - content.js
  - background.js
  - overlay.js
        ↓ HTTP POST
[Local Analysis Service]
  - app/ml_api.py
  - src/features/rule_features.py
  - src/explainability/rule_explainer.py
  - saved models
        ↓
[Overlay Result]
```

## 단계별 계획

### 1. 현재 통합
- Mail_Shield의 extension 폴더를 통합 프로젝트로 이관
- PshingMail_Detection의 분석 서비스 코드를 통합 프로젝트로 이관
- 문서로 역할 분리와 책임을 명확히 함

### 2. 다음 정리 작업
- extension 내부 중복 rule engine을 최소 fallback 용도로 축소
- analysis-service의 응답 포맷을 shared 계약에 맞춰 고정
- run script 추가 (`start-analysis`, `start-dev` 등)
- 확장 팝업에서 API 주소와 헬스체크를 직접 확인 가능하게 개선
- `/health` 엔드포인트로 서비스 상태 점검 가능하게 개선

### 3. 이후 확장
- Outlook/Gmail 헤더 수집 강화
- 도메인 평판, SPF/DKIM/DMARC 연계
- 설명 결과를 레벨/카테고리별로 구조화
- 데스크톱 앱 또는 관리 UI 추가 가능

## 현재 의사결정
- 코어 분석 엔진은 Python 기반으로 유지
- 브라우저 확장은 JS로 유지
- 두 시스템은 HTTP API 계약으로 연결
- 중장기적으로는 shared schema를 코드 생성 또는 JSON schema로 고정하는 것이 바람직함
