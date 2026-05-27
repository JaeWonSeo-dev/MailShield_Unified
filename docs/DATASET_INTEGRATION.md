# Dataset Integration

## 확인한 원본 데이터셋 위치
외부 학습 데이터셋은 다음 경로에서 확인했다.

- `C:\Sjw_dev\Coding\PshingMail_Detection\data\raw\phishing_kaggle\phishing_email.csv`
- `C:\Sjw_dev\Coding\PshingMail_Detection\data\raw\phishing_kaggle\CEAS_08.csv`
- `C:\Sjw_dev\Coding\PshingMail_Detection\data\raw\phishing_kaggle\Enron.csv`
- `C:\Sjw_dev\Coding\PshingMail_Detection\data\raw\phishing_kaggle\Ling.csv`
- `C:\Sjw_dev\Coding\PshingMail_Detection\data\raw\phishing_kaggle\Nazario.csv`
- `C:\Sjw_dev\Coding\PshingMail_Detection\data\raw\phishing_kaggle\Nigerian_Fraud.csv`
- `C:\Sjw_dev\Coding\PshingMail_Detection\data\raw\phishing_kaggle\SpamAssasin.csv`
- `C:\Sjw_dev\Coding\PshingMail_Detection\data\raw\enron\emails.csv`
- `C:\Sjw_dev\Coding\PshingMail_Detection\data\processed\train.csv`
- `C:\Sjw_dev\Coding\PshingMail_Detection\data\processed\val.csv`
- `C:\Sjw_dev\Coding\PshingMail_Detection\data\processed\test.csv`

## 핵심 컬럼
### `raw/phishing_kaggle/phishing_email.csv`
- `text_combined`
- `label`

### `raw/enron/emails.csv`
- `file`
- `message`

### `processed/train.csv` 등
- `source`
- `subject`
- `body`
- `sender`
- `reply_to`
- `urls_raw`
- `label_type`
- `label`
- `email_id`
- `subject_clean`
- `body_clean`
- `sender_domain`
- `reply_to_domain`
- `urls`
- `url_count`
- `has_suspicious_url`
- `text_combined`
- `char_count`

## 통합 원칙
- 데이터셋은 대용량이므로 `MailShield_Unified` 안으로 중복 복사하지 않는다.
- `MailShield_Unified/analysis-service`는 외부 데이터셋 경로를 직접 참조해 전처리/학습/검증한다.
- 최종 제품은 Chrome Extension이지만, 모델 품질 관리는 이 데이터셋을 기준으로 재학습 가능해야 한다.

## 제공 스크립트
### 1. 데이터셋 프로파일 생성
```powershell
cd C:\Sjw_dev\Coding\MailShield_Unified\analysis-service
python scripts/profile_external_dataset.py --dataset-root C:\Sjw_dev\Coding\PshingMail_Detection\data
```

출력:
- `analysis-service/reports/dataset_profile.json`

### 2. 외부 데이터셋으로 모델 재학습
```powershell
cd C:\Sjw_dev\Coding\MailShield_Unified\analysis-service
python scripts/train_from_external_dataset.py --dataset-root C:\Sjw_dev\Coding\PshingMail_Detection\data --skip-preprocess
```

또는 루트에서:
```powershell
cd C:\Sjw_dev\Coding\MailShield_Unified
./train-analysis-from-dataset.ps1
```

## 현재 기본 동작
- `--skip-preprocess` 사용 시: 이미 존재하는 `processed/train.csv`, `val.csv`, `test.csv`를 바로 사용
- 옵션 제거 시: 외부 `raw/`를 다시 읽어 `processed/`를 재생성한 뒤 학습
- 학습 시작 전 preflight에서 데이터셋 루트, `skip-preprocess` 여부, XGBoost 장치 설정(`cpu`/`cuda`)을 로그로 출력하고, 필요한 processed split 파일 누락 시 즉시 중단한다.

## 기대 효과
- 확장에 연결된 분석 모델을, 네가 실제로 사용했던 원본 학습 데이터셋 기반으로 다시 관리 가능
- 통합 프로젝트에서 데이터셋 출처와 학습 경로가 명확해짐
- 이후 성능 개선이나 재학습 작업도 `MailShield_Unified` 안에서 재현 가능
