# 5-Day PE-Only Training Workflow

This project now supports a PE-only training loop based on curated sources,
prepared subsets, and external model training.

## Goals

- Day 1-2: reach smoke scale (`~100 SAFE`, `~100 ENCRYPTED`)
- Day 3-4: reach pilot scale (`~1000 SAFE`, `~1000 ENCRYPTED`)
- Day 5: train and validate a usable local model

## Day 1: Plan and source layout

```powershell
python main.py --search-training-sources --kind both --pe-only
python main.py --plan-training-source --kind both --scale smoke
python main.py --plan-training-source --kind both --scale pilot
python main.py --training-progress --scale smoke
```

Create manifests for the default sources:

```powershell
python main.py --download-training-source --source-id napierone --kind safe --scale pilot
python main.py --download-training-source --source-id trusted-vendors --kind safe --scale pilot
python main.py --download-training-source --source-id sorel20m-github --kind encrypted --scale pilot
python main.py --download-training-source --source-id sorel20m-aws --kind encrypted --scale pilot
```

## Day 2: Fill SAFE sources and prepare

Copy PE files into:

- `datasets/sources/safe/trusted-vendors`
- `datasets/sources/safe/napierone`

Prepare them:

```powershell
python main.py --prepare-training-source --source-id trusted-vendors --kind safe --scale smoke
python main.py --prepare-training-source --source-id napierone --kind safe --scale smoke
python main.py --training-progress --scale smoke
```

## Day 3: Fill ENCRYPTED sources and prepare

Copy disarmed PE samples into:

- `datasets/sources/encrypted/sorel20m-github`
- optionally `datasets/sources/encrypted/sorel20m-aws`

Prepare them:

```powershell
python main.py --prepare-training-source --source-id sorel20m-github --kind encrypted --scale smoke
python main.py --training-progress --scale smoke
```

## Day 4: Train smoke, then move to pilot

When smoke scale is ready:

```powershell
python main.py --train-from-source-plan --scale smoke
```

Then continue filling source folders and re-prepare for pilot:

```powershell
python main.py --prepare-training-source --source-id trusted-vendors --kind safe --scale pilot
python main.py --prepare-training-source --source-id napierone --kind safe --scale pilot
python main.py --prepare-training-source --source-id sorel20m-github --kind encrypted --scale pilot
python main.py --training-progress --scale pilot
```

If pilot becomes ready:

```powershell
python main.py --train-from-source-plan --scale pilot
```

## Day 5: Validate false positives

Run a scan on a small benign PE folder:

```powershell
python main.py --scan "C:\path\to\benign_pe_smoke"
```

Review:

- false positives on vendor installers
- false negatives on a few disarmed PE malware samples
- prepared dataset counts in `datasets/datasets/`
- active model and backups in `models/`

## Commands Summary

```powershell
python main.py --search-training-sources --kind both --pe-only
python main.py --plan-training-source --kind both --scale pilot
python main.py --training-progress --scale pilot
python main.py --download-training-source --source-id <id> --kind <safe|encrypted> --scale pilot
python main.py --prepare-training-source --source-id <id> --kind <safe|encrypted> --scale pilot
python main.py --train-from-source-plan --scale pilot
python main.py --train-external --safe-dir "<path>" --encrypted-dir "<path>" --output-csv "<path>"
```
