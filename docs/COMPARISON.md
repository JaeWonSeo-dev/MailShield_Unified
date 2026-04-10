# Mail_Shield vs PshingMail_Detection

## Mail_Shield

성격:
- 브라우저 확장 기반 실사용 MVP
- Gmail / Outlook Web에서 직접 메일을 읽고 오버레이 표시

강점:
- 실제 사용 시나리오와 가장 가까움
- DOM 기반 메일 수집이 이미 구현됨
- overlay UI와 background 호출 구조가 있음
- 로컬 ML API와 연결하는 자리가 이미 존재함

약점:
- 탐지 로직이 JS 규칙 엔진 위주라 단순함
- 모델 학습/실험/설명 파이프라인이 약함
- 일부 규칙이 다른 프로젝트와 중복 구현되어 있음

## PshingMail_Detection

성격:
- 설명 가능한 피싱 메일 분석 엔진 프로젝트
- 전처리 + 룰 피처 + TF-IDF + ML 모델 + 설명 생성 중심

강점:
- 탐지 로직이 더 깊고 구조적임
- 저장된 모델과 feature extractor 사용 가능
- `ml_api.py`를 통해 로컬 분석 서비스로 바로 활용 가능
- 테스트와 설정 파일 구조가 있음

약점:
- 실제 브라우저 메일 환경에서 바로 동작하지 않음
- Streamlit 데모는 제품 UX라기보다 실험/포트폴리오 성격이 강함

## 통합 결론

### 살릴 것
- 사용자 경험, 실행 진입점: `Mail_Shield`
- 분석 모델, 설명 엔진: `PshingMail_Detection`

### 버리지 말아야 할 핵심
- `Mail_Shield`의 메일 컨텍스트 수집 구조
- `PshingMail_Detection`의 rule feature / explainer / ml_api 구조

### 추천 방향
- 확장은 메일 수집과 표시 담당
- 분석 서비스는 JSON 기반 판정 담당
- 공통 분석 계약을 중심으로 둘을 느슨하게 연결
