# PhishingMail Detection (MailShield Unified)

`Mail_Shield`의 크롬 확장 구조에 `PshingMail_Detection`의 학습 기반 탐지 모델을 연결한 프로젝트입니다.

## 핵심 목적
이 프로젝트의 최종 산출물은 **웹페이지가 아니라 크롬 확장 프로그램**입니다.

즉, 목표는 다음 한 줄로 요약됩니다.

> **Mail Shield가 실제 메일을 읽는 지점에 PshingMail Detection의 탐지 모델을 연결해, 사용자가 Gmail/Outlook 메일을 열면 즉시 피싱 여부를 판정한다.**

## 역할 분리
- **extension/**
  - Mail Shield 계승
  - Gmail / Outlook Web에서 메일 문맥 수집
  - 분석 요청 전송
  - 오버레이/경고 UI 표시
- **analysis-service/**
  - PshingMail Detection 계승
  - 학습 모델 + feature extractor + rule explainer 보유
  - `/analyze` API로 확장 요청을 받아 판정 반환

## 중요 원칙
- 최종 제품은 **Chrome Extension**이다.
- 별도 웹페이지 제품은 만들지 않는다.
- `PshingMail_Detection`의 웹 데모 성격 코드는 최종 사용자 경로가 아니다.
- 확장은 수집/UI를 담당하고, 분석 서비스는 모델 추론을 담당한다.

## 폴더 구조
```text
MailShield_Unified/
├─ extension/                # 최종 제품: Chrome extension
├─ analysis-service/         # PshingMail_Detection 모델/추론 엔진
│  ├─ app/
│  │  ├─ ml_api.py           # 확장이 호출하는 로컬 분석 API
│  │  └─ streamlit_app.py    # 레거시 데모용 파일 (최종 제품 경로 아님)
│  ├─ src/
│  ├─ models/
│  ├─ tests/
│  ├─ config.yaml
│  └─ requirements.txt
├─ shared/
│  └─ analysis-contract.md
└─ docs/
   ├─ COMPARISON.md
   └─ INTEGRATION_PLAN.md
```

## 실행 방식
### 1) 분석 서비스 실행
가장 간단한 방법:
```powershell
./start-analysis.ps1
```

수동 실행:
```bash
cd analysis-service
pip install -r requirements.txt
python app/ml_api.py
```

기본 주소:
- `http://127.0.0.1:8765/analyze`
- `http://127.0.0.1:8765/health`

### 2) 확장 로드
1. Chrome/Edge에서 `chrome://extensions` 열기
2. Developer mode 켜기
3. `Load unpacked` 선택
4. `extension/` 폴더 선택
5. 확장 팝업에서 API 주소가 `http://127.0.0.1:8765/analyze` 인지 확인
6. `연결 확인` 버튼으로 health 체크
7. Gmail 또는 Outlook Web에서 메일 열기
8. 메일을 클릭하면 자동 분석 오버레이 표시

## 현재 상태
- Mail Shield 확장 구조와 PshingMail Detection 분석 엔진 통합 완료
- 확장 → 분석 서비스 공통 JSON 계약 확장 완료
- 실시간 분석 결과에 `verdict`, `confidence`, 링크/첨부 기반 입력 반영 완료
- 확장 브랜딩을 `PhishingMail Detection` 기준으로 통일 중
- 실행/테스트 스크립트 정리 완료
- 현재 초점: **웹 UI 제거가 아니라, 확장 중심 구조를 더 명확히 하고 모델 연결을 안정화하는 것**

## 다음 작업 우선순위
1. 확장 내부 fallback rule 로직 축소
2. 실제 메일 샘플 기준 정확도 검증
3. 확장 UX 정리 및 패키징 마감
4. 필요 시 레거시 웹 데모 코드 정리/제거
