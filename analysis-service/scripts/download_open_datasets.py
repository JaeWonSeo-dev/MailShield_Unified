from __future__ import annotations

import argparse
import logging
import shutil
import urllib.request
from pathlib import Path


GITHUB_BASE = "https://raw.githubusercontent.com/rokibulroni/Phishing-Email-Dataset/main"
GITHUB_CSV_FILES = [
    "CEAS_08.csv",
    "Enron.csv",
    "Ling.csv",
    "Nazario.csv",
    "Nigerian_Fraud.csv",
    "SpamAssasin.csv",
]

HF_ZEFANG_URL = "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv"
HF_BIG_SPAM_HAM_PHISH_URL = (
    "https://huggingface.co/datasets/locuoco/"
    "the-biggest-spam-ham-phish-email-dataset-300000/resolve/main/df.csv"
)

ROOT = Path(__file__).resolve().parents[1]


def download(url: str, target: Path, force: bool = False) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.stat().st_size > 0 and not force:
        logging.info("exists: %s", target)
        return

    tmp = target.with_suffix(target.suffix + ".tmp")
    logging.info("download: %s -> %s", url, target)
    with urllib.request.urlopen(url, timeout=120) as response, open(tmp, "wb") as f:
        shutil.copyfileobj(response, f)
    tmp.replace(target)
    logging.info("saved: %s (%.1f MB)", target, target.stat().st_size / 1024 / 1024)


def main() -> None:
    parser = argparse.ArgumentParser(description="Download public phishing email datasets into analysis-service/data/raw")
    parser.add_argument("--output-root", default=str(ROOT / "data" / "raw"), help="Target raw data directory")
    parser.add_argument("--force", action="store_true", help="Re-download existing files")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    output_root = Path(args.output_root)
    phishing_dir = output_root / "phishing_kaggle"

    for filename in GITHUB_CSV_FILES:
        download(f"{GITHUB_BASE}/{filename}", phishing_dir / filename, force=args.force)

    # The existing loader expects this filename for the Kaggle-style text+label dataset.
    download(HF_ZEFANG_URL, phishing_dir / "phishing_email.csv", force=args.force)
    download(HF_BIG_SPAM_HAM_PHISH_URL, output_root / "big_spam_ham_phish" / "df.csv", force=args.force)

    logging.info("Dataset download complete: %s", output_root)


if __name__ == "__main__":
    main()
