import sys
import unittest
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.ml_api import build_input_row, predict_email
from src.data.augmentation import augment_training_data
from src.data.preprocessor import preprocess, split_dataset
from src.explainability.rule_explainer import generate_rule_explanation
from src.features.model_text import build_model_text_record
from src.features.rule_features import add_rule_features, extract_rule_features
from src.features.text_features import TextFeatureExtractor
from src.models.baseline import find_best_threshold


class TestPipelineSmoke(unittest.TestCase):
    def test_augmentation_increases_training_rows(self):
        df = pd.DataFrame([
            {
                "email_id": "h1",
                "source": "unit",
                "subject": "Normal memo",
                "body": "Team meeting at 3pm",
                "sender": "manager@company.com",
                "reply_to": "manager@company.com",
                "label_type": "ham",
                "label": 0,
                "text_combined": "Normal memo Team meeting at 3pm",
            },
            {
                "email_id": "p1",
                "source": "unit",
                "subject": "Review required",
                "body": "Please review this message",
                "sender": "support@example.com",
                "reply_to": "support@example.com",
                "label_type": "phishing",
                "label": 1,
                "text_combined": "Review required Please review this message",
            },
        ])

        out = augment_training_data(
            df,
            {
                "enabled": True,
                "threat_sample_ratio": 1.0,
                "variants_per_sample": 2,
                "random_seed": 7,
            },
        )

        self.assertGreater(len(out), len(df))
        self.assertTrue((out["label"] == 1).sum() >= 3)

    def test_preprocess_extracts_domains_and_urls(self):
        df = pd.DataFrame([
            {
                "email_id": "e1",
                "source": "unit",
                "subject": "Urgent Verify",
                "body": "<p>Click https://example.tk/login now</p>",
                "sender": "alert@paypal-secure.tk",
                "reply_to": "help@paypal.com",
                "label_type": "phishing",
                "label": 1,
            }
        ])

        out = preprocess(df)
        self.assertEqual(len(out), 1)
        self.assertEqual(out.loc[0, "sender_domain"], "paypal-secure.tk")
        self.assertEqual(out.loc[0, "reply_to_domain"], "paypal.com")
        self.assertGreaterEqual(out.loc[0, "url_count"], 1)
        self.assertNotIn("escapenumber", out.loc[0, "text_combined"].lower())

    def test_group_split_keeps_duplicate_content_in_one_split(self):
        rows = []
        for i in range(100):
            suffix = chr(65 + (i % 26)) + chr(65 + ((i // 26) % 26))
            body = "Repeated invoice body" if i < 6 else f"Unique body token {suffix}"
            rows.append({
                "email_id": f"e{i}",
                "source": "unit",
                "subject": "Subject",
                "body": body,
                "sender": "sender@example.com",
                "reply_to": "sender@example.com",
                "label_type": "phishing" if i % 2 else "ham",
                "label": i % 2,
            })
        df = preprocess(pd.DataFrame(rows))

        train_df, val_df, test_df = split_dataset(df, train_ratio=0.6, val_ratio=0.2, random_seed=7)
        split_names = {}
        for split_name, split_df in [("train", train_df), ("val", val_df), ("test", test_df)]:
            for group in split_df["content_group"].unique():
                self.assertNotIn(group, split_names)
                split_names[group] = split_name

    def test_rule_features_and_explanation(self):
        row = {
            "subject": "URGENT: Verify your account",
            "body": (
                "Dear Customer, your account will be suspended. "
                "Enter your password and credit card at http://paypal-check.tk"
            ),
            "text_combined": (
                "URGENT verify your account. Dear Customer, enter your password and credit card at http://paypal-check.tk"
            ),
            "sender": "security@paypal-check.tk",
            "reply_to": "security@paypal-check.tk",
            "urls": ["http://paypal-check.tk"],
        }

        feats = extract_rule_features(row)
        self.assertEqual(feats["has_http_url"], 1)
        self.assertEqual(feats["has_suspicious_url"], 1)
        self.assertEqual(feats["credential_request"], 1)
        self.assertEqual(feats["generic_greeting"], 1)

        reasons = generate_rule_explanation(feats)
        self.assertTrue(len(reasons) > 0)
        self.assertTrue(any(r["severity"] == "high" for r in reasons))

    def test_link_only_lure_detection(self):
        row = {
            "subject": "Invoice review request",
            "body": "Please review the shared document at https://vendor-portal.co/docs/review and confirm.",
            "text_combined": "Invoice review request Please review the shared document at https://vendor-portal.co/docs/review and confirm.",
            "sender": "procurement@vendor-portal.co",
            "reply_to": "procurement@vendor-portal.co",
            "urls": ["https://vendor-portal.co/docs/review"],
        }

        feats = extract_rule_features(row)
        self.assertEqual(feats["credential_request"], 0)
        self.assertGreaterEqual(feats["link_lure_score"], 2)
        self.assertEqual(feats["link_only_lure"], 1)

    def test_business_and_attachment_lure_detection(self):
        row = {
            "subject": "Urgent payroll update attached",
            "body": "Dear User, see attached invoice and payroll adjustment form. Open attachment immediately.",
            "text_combined": "Urgent payroll update attached Dear User, see attached invoice and payroll adjustment form. Open attachment immediately.",
            "sender": "hr@example.com",
            "reply_to": "hr@example.com",
            "urls": [],
        }

        feats = extract_rule_features(row)
        self.assertEqual(feats["generic_greeting"], 1)
        self.assertEqual(feats["attachment_lure"], 1)
        self.assertGreaterEqual(feats["business_lure_score"], 1)
        self.assertGreaterEqual(feats["urgency_score"], 1)

    def test_unusual_payment_and_reward_detection(self):
        row = {
            "subject": "Claim your reward now",
            "body": "Congratulations dear customer. Claim your prize and send a Bitcoin payment to release the bonus.",
            "text_combined": "Claim your reward now Congratulations dear customer. Claim your prize and send a Bitcoin payment to release the bonus.",
            "sender": "promo@reward-center.xyz",
            "reply_to": "promo@reward-center.xyz",
            "urls": ["http://reward-center.xyz/claim"],
        }

        feats = extract_rule_features(row)
        self.assertEqual(feats["reward_offer"], 1)
        self.assertEqual(feats["unusual_payment_request"], 1)
        self.assertEqual(feats["generic_greeting"], 1)
        self.assertGreaterEqual(feats["rule_risk_score"], 4)

    def test_predict_email_accepts_extension_payload(self):
        payload = {
            "provider": "gmail",
            "sender": "security@paypal-check.tk",
            "sender_name": "PayPal Security",
            "reply_to": "help@paypal.com",
            "subject": "Urgent: verify your account",
            "body": "Click the secure login below and verify your password now.",
            "body_snippet": "Click the secure login below",
            "links": [
                {"href": "http://paypal-check.tk/login", "text": "Verify now"}
            ],
            "attachments": ["statement.zip"],
            "source_url": "https://mail.google.com/mail/u/0/#inbox/demo",
            "coverage": {"messageCount": 1, "textLength": 88, "linkCount": 1, "attachmentCount": 1},
        }

        row, feats, urls, attachments = build_input_row(payload)
        self.assertEqual(row["provider"], "gmail")
        self.assertEqual(len(urls), 1)
        self.assertEqual(len(attachments), 1)
        self.assertEqual(feats["has_http_url"], 1)

        result = predict_email(payload)
        self.assertIn(result["verdict"], {"phishing", "legit"})
        self.assertIn("confidence", result)
        self.assertEqual(result["attachment_count"], 1)
        self.assertEqual(result["provider"], "gmail")

    def test_text_features_fit_transform(self):
        base_df = pd.DataFrame([
            {
                "subject": "hello",
                "body": "team sync tomorrow",
                "text_combined": "hello team sync tomorrow",
                "sender": "manager@company.com",
                "reply_to": "manager@company.com",
            },
            {
                "subject": "urgent account",
                "body": "verify password now http://evil.tk",
                "text_combined": "urgent account verify password now http://evil.tk",
                "sender": "security@evil.tk",
                "reply_to": "help@paypal.com",
            },
        ])

        df = add_rule_features(base_df)
        extractor = TextFeatureExtractor(max_features=200, min_df=1, max_df=1.0)
        X = extractor.fit_transform(df)
        self.assertEqual(X.shape[0], 2)
        self.assertGreater(X.shape[1], 10)

    def test_text_only_extractor_excludes_rule_features(self):
        df = pd.DataFrame([
            {
                "subject": "urgent account",
                "body": "verify password now http://evil.tk",
                "text_combined": "urgent account verify password now sender_domain=evil.tk url=http://evil.tk",
                "sender": "security@evil.tk",
                "reply_to": "help@paypal.com",
            },
            {
                "subject": "hello",
                "body": "team sync tomorrow",
                "text_combined": "hello team sync tomorrow sender_domain=company.com",
                "sender": "manager@company.com",
                "reply_to": "manager@company.com",
            },
        ])

        extractor = TextFeatureExtractor(max_features=200, min_df=1, max_df=1.0, include_rule_features=False)
        X = extractor.fit_transform(add_rule_features(df))

        self.assertEqual(X.shape[1], len(extractor.get_tfidf_feature_names()))
        self.assertFalse(extractor.include_rule_features)

    def test_chi2_feature_selection_reduces_tfidf_features(self):
        df = pd.DataFrame([
            {"text_combined": "secure login verify account sender_domain=evil.test", "label": 1},
            {"text_combined": "team meeting schedule sender_domain=company.test", "label": 0},
            {"text_combined": "password update required url=http://evil.test", "label": 1},
            {"text_combined": "project planning memo sender_domain=company.test", "label": 0},
        ])

        extractor = TextFeatureExtractor(
            max_features=200,
            min_df=1,
            max_df=1.0,
            include_rule_features=False,
            feature_selection={"enabled": True, "method": "chi2", "k": 5},
        )
        X = extractor.fit_transform(df)

        self.assertEqual(X.shape[1], 5)
        self.assertEqual(len(extractor.get_tfidf_feature_names()), 5)

    def test_model_text_includes_metadata_as_learnable_tokens(self):
        text = build_model_text_record({
            "subject": "Payroll update",
            "body": "Please review the document.",
            "sender": "hr@company.com",
            "sender_domain": "company.com",
            "reply_to": "external@example.net",
            "reply_to_domain": "example.net",
            "urls": ["https://example.net/review"],
            "attachments": ["payroll.zip"],
        })

        self.assertIn("Payroll update", text)
        self.assertIn("sender_domain=company.com", text)
        self.assertIn("reply_to_domain=example.net", text)
        self.assertIn("url=https://example.net/review", text)
        self.assertIn("attachment=payroll.zip", text)

    def test_threshold_tuning_uses_model_scores(self):
        class TinyModel:
            def predict_proba(self, X):
                return pd.DataFrame([[0.9, 0.1], [0.6, 0.4], [0.2, 0.8]]).values

        best = find_best_threshold(TinyModel(), None, pd.Series([0, 1, 1]).values, metric="f1")

        self.assertLessEqual(best["threshold"], 0.4)
        self.assertEqual(best["f1"], 1.0)

    def test_batch_and_single_rule_features_are_consistent_for_url_domain_mismatch(self):
        row = {
            "subject": "PayPal security notice",
            "body": "Please verify your PayPal account here: http://paypal-check.tk/login",
            "text_combined": "PayPal security notice Please verify your PayPal account here: http://paypal-check.tk/login",
            "sender": "security@paypal-check.tk",
            "reply_to": "help@paypal.com",
            "urls": ["http://paypal-check.tk/login"],
        }

        single = extract_rule_features(row)
        batch_df = add_rule_features(pd.DataFrame([row]))

        self.assertEqual(single["url_domain_mismatch"], int(batch_df.loc[0, "url_domain_mismatch"]))
        self.assertEqual(single["rule_risk_score"], int(batch_df.loc[0, "rule_risk_score"]))
        self.assertEqual(single["has_suspicious_url"], int(batch_df.loc[0, "has_suspicious_url"]))


if __name__ == "__main__":
    unittest.main()
