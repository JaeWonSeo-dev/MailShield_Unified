# PhishingMail Detection (MailShield Unified)

`Mail_Shield`와 `PshingMail_Detection`을 통합한 프로젝트입니다.

## 제품 방향
이 프로젝트는 **Mail Shield의 크롬 확장 방식**에 **PshingMail_Detection의 학습 기반 분석 엔진**을 결합해,
사용자가 실제 Gmail/Outlook 메일을 열람하는 순간 **실시간으로 피싱 메일 여부를 판정**하는 것을 목표로 합니다.

즉 역할은 다음처럼 분리됩니다.
- **extension/** → 실제 메일을 읽고 화면에 경고를 띄우는 크롬 확장
- **analysis-service/** → 학습된 모델 + 룰 기반 설명으로 메일을 판정하는 로컬 AI 분석 서비스

## 목표
- 브라우저 확장에서 Gmail/Outlook 메일을 자동 수집
- 로컬 분석 서비스에서 규칙 기반 + ML 기반 피싱 분석 수행
- 결과를 확장 오버레이에서 설명 가능한 형태로 표시
- 웹과 프로그램이 따로 노는 것이 아니라, 같은 분석 코어를 공유하도록 구조화

## 통합 원칙
- **UI/실행 환경**은 `Mail_Shield`를 기준으로 유지
- **분석 엔진/모델**은 `PshingMail_Detection`를 기준으로 유지
- 공통 입출력 계약은 `shared/analysis-contract.md`에 문서화

## 폴더 구조
```text
MailShield_Unified/
├─ extension/                # Mail_Shield 기반 브라우저 확장
├─ analysis-service/         # PshingMail_Detection 기반 로컬 분석 엔진
│  ├─ app/
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

## 빠른 실행
### 1) 분석 서비스 실행
```bash
cd analysis-service
pip install -r requirements.txt
python app/ml_api.py
```

기본 주소:
- `http://127.0.0.1:8765/analyze`

### 2) 확장 로드
1. Chrome/Edge에서 `chrome://extensions` 열기
2. Developer mode 켜기
3. `Load unpacked` 선택
4. `extension/` 폴더 선택
5. Gmail 또는 Outlook Web에서 메일 열기
6. 필요하면 확장 아이콘을 눌러 API 주소를 확인/변경

## 현재 상태
- 통합 폴더 생성 완료
- 확장 코드 이관 완료
- 로컬 분석 엔진 이관 완료
- 계약 문서/비교 문서 추가 완료
- 확장 → 분석 서비스 공통 JSON 계약 확장 완료
- 실시간 분석 결과에 `verdict`, `confidence`, 링크/첨부 기반 입력 반영 완료
- 확장 브랜딩을 `PhishingMail Detection` 기준으로 통일 시작
- 실행/테스트 스크립트의 사용 흐름 정리 완료
- 다음 단계: 중복 룰 로직 최소화, 실제 메일 데이터로 정확도 검증, 패키징 마감
