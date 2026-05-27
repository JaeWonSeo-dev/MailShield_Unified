# Training Results

- generated_at: 2026-05-27T21:31:34
- classification_mode: multiclass
- primary_metric: f1_macro
- class_balance: {'ham': 124697, 'spam': 102101, 'phishing': 38051}

## logistic_regression

### val

- accuracy: 0.9383
- f1_macro: 0.9147
- precision_macro: 0.9092
- recall_macro: 0.9209
- roc_auc: 0.9881
- ham_f1: 0.9825
- spam_f1: 0.924
- phishing_f1: 0.8377

### test

- accuracy: 0.9359
- f1_macro: 0.911
- precision_macro: 0.9057
- recall_macro: 0.9169
- roc_auc: 0.9883
- ham_f1: 0.9815
- spam_f1: 0.918
- phishing_f1: 0.8334

## xgboost

Skipped for the active 3-class production target. `LogisticRegressionCV` is the operating model.
