# Integration Plan

## 최종 제품 정의
최종 제품은 **Chrome Extension**이다.

이 프로젝트는 별도 웹페이지 기반 피싱 분석 서비스를 만드는 것이 아니라,
**Mail Shield의 메일 수집/오버레이 흐름에 PshingMail Detection의 학습 모델을 연결하는 것**이 목적이다.

## 목표 아키텍처

```text
[Gmail / Outlook Web]
        ↓
[Mail Shield 기반 Chrome Extension]
  - content.js
  - background.js
  - overlay.js
        ↓ HTTP POST
[PshingMail Detection 기반 Local Analysis Service]
  - app/ml_api.py
  - src/features/rule_features.py
  - src/explainability/rule_explainer.py
  - saved models
        ↓
[Extension Overlay Result]
```

## 현재 결정사항
- **수집/UI는 Mail Shield 기준 유지**
- **탐지 모델/설명 엔진은 PshingMail Detection 기준 유지**
- 연결 방식은 로컬 HTTP API (`/analyze`) 사용
- Streamlit 같은 웹 데모 경로는 최종 사용자 경로로 보지 않음

## 단계별 계획

### 1. 이미 완료된 작업
- Mail Shield의 extension 폴더 통합
- PshingMail Detection의 분석 서비스 코드 통합
- 확장과 분석 서비스 간 공통 JSON 계약 정리
- 확장에서 링크/첨부/본문 문맥까지 분석 서비스로 전달하도록 확장

### 2. 현재 정리 작업
- extension 내부 중복 rule engine을 최소 fallback 용도로 축소
- analysis-service의 응답 포맷을 shared 계약에 맞춰 유지
- 확장 팝업에서 API 주소와 헬스체크를 직접 확인 가능하게 유지
- 문서에서 웹페이지 제품처럼 보이는 표현 제거

### 3. 이후 우선 작업
- Gmail/Outlook 헤더 수집 강화
- 실제 피싱 메일 샘플 기반 회귀 테스트 추가
- 확장 UI에서 위험 이유를 더 사용자 친화적으로 노출
- 필요 시 레거시 데모 파일 정리
