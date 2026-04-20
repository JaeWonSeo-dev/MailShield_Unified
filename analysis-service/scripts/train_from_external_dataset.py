from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

DEFAULT_DATASET_ROOT = Path(r"C:\Sjw_dev\Coding\PshingMail_Detection\data")
ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config.yaml"


def main() -> None:
    parser = __import__("argparse").ArgumentParser(description="Train analysis-service models from external PshingMail_Detection dataset")
    parser.add_argument("--dataset-root", default=str(DEFAULT_DATASET_ROOT), help="Path to external data root containing raw/ and processed/")
    parser.add_argument("--skip-preprocess", action="store_true", help="Skip preprocessing and use existing processed train/val/test csvs")
    args = parser.parse_args()

    dataset_root = Path(args.dataset_root)
    raw_dir = dataset_root / "raw"
    processed_dir = dataset_root / "processed"

    if not raw_dir.exists() and not processed_dir.exists():
        raise SystemExit(f"Dataset root not found or invalid: {dataset_root}")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    logger = logging.getLogger("train_from_external_dataset")

    with open(CONFIG_PATH, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    original_paths = dict(config.get("paths", {}))
    config["paths"]["raw_data_dir"] = str(raw_dir)
    config["paths"]["processed_data_dir"] = str(processed_dir)

    backup_path = CONFIG_PATH.with_suffix(".yaml.bak")
    shutil.copy2(CONFIG_PATH, backup_path)

    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)

        if not args.skip_preprocess:
            logger.info("Preprocessing external dataset into processed splits...")
            subprocess.run([sys.executable, str(ROOT / "src" / "data" / "preprocessor.py")], check=True, cwd=str(ROOT))
        else:
            logger.info("Skipping preprocessing and using existing processed CSV files")

        logger.info("Training models from external dataset...")
        subprocess.run([sys.executable, str(ROOT / "src" / "models" / "baseline.py")], check=True, cwd=str(ROOT))
        logger.info("Training complete")
    finally:
        shutil.copy2(backup_path, CONFIG_PATH)
        backup_path.unlink(missing_ok=True)
        logger.info("Restored original config.yaml paths")


if __name__ == "__main__":
    main()
