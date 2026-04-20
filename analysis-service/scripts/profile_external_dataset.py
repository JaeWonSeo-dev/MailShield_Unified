from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

DEFAULT_DATASET_ROOT = Path(r"C:\Sjw_dev\Coding\PshingMail_Detection\data")


def summarize_csv(path: Path, nrows: int = 2000) -> dict:
    df = pd.read_csv(path, nrows=nrows)
    summary = {
        "path": str(path),
        "exists": path.exists(),
        "columns": list(df.columns),
        "sample_rows": len(df),
    }
    if "label" in df.columns:
        summary["label_distribution_sample"] = {str(k): int(v) for k, v in df["label"].value_counts(dropna=False).to_dict().items()}
    if "label_type" in df.columns:
        summary["label_type_distribution_sample"] = {str(k): int(v) for k, v in df["label_type"].value_counts(dropna=False).to_dict().items()}
    return summary


def build_profile(dataset_root: Path) -> dict:
    raw_root = dataset_root / "raw"
    processed_root = dataset_root / "processed"

    files = {
        "raw_phishing_email": raw_root / "phishing_kaggle" / "phishing_email.csv",
        "raw_enron": raw_root / "enron" / "emails.csv",
        "processed_train": processed_root / "train.csv",
        "processed_val": processed_root / "val.csv",
        "processed_test": processed_root / "test.csv",
    }

    profile = {
        "dataset_root": str(dataset_root),
        "files": {},
    }

    for key, path in files.items():
        if path.exists():
            profile["files"][key] = summarize_csv(path)
        else:
            profile["files"][key] = {"path": str(path), "exists": False}

    return profile


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Profile the external PshingMail_Detection dataset")
    parser.add_argument("--dataset-root", default=str(DEFAULT_DATASET_ROOT))
    parser.add_argument("--output", default="reports/dataset_profile.json")
    args = parser.parse_args()

    dataset_root = Path(args.dataset_root)
    profile = build_profile(dataset_root)

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = Path(__file__).resolve().parents[1] / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Dataset profile written to {output_path}")
