#!/usr/bin/env python3
"""
sigmadft_label.py - Label a Plaso CSV timeline using atlas rules.

Detection replicates SigmaDFT (https://github.com/forensic-timeline/sigmadft):
  - each row is matched as the text
        "{timestamp_desc}-{source} {message} {source}-{source_long}-{parser}"
  - rule `detection.keywords` may be a plain list or a dict keyed by modifiers
    such as '|all|re':
        re  -> each keyword is a regex (re.search), otherwise substring match
        all -> every keyword must match, otherwise any keyword is enough
  - `logsource` and `condition` are not used for filtering (same as SigmaDFT).

Output: the input CSV with all rows kept, plus a `label` column holding
`high_level_event.type` of every matching rule (fallback: rule `title`),
joined with "; ". Rows matching no rule get an empty label.

Standalone: needs only Python 3.9+ and PyYAML. Rules are discovered under
../rules relative to this script, so the atlas folder can be moved anywhere.

Usage:
    python tools/sigmadft_label.py -i timeline.csv -o labeled.csv [-r RULES_DIR]
"""

import argparse
import csv
import re
import sys
import time
from pathlib import Path

import yaml

LABEL_COLUMN = "label"
LABEL_SEPARATOR = "; "
DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def discover_rules(rules_dir: Path):
    """All *.yml / *.yaml files under rules_dir, sorted like SigmaDFT."""
    files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
    return sorted(files, key=lambda p: "/" + str(p.relative_to(rules_dir)))


def load_rule(path: Path):
    """Parse one rule into (label, keywords, use_regex, require_all)."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("rule file is not a YAML mapping")

    detection = data.get("detection", {})
    if not isinstance(detection, dict):
        raise ValueError("detection must be a mapping")

    keywords = detection.get("keywords", [])
    modifiers = []
    if isinstance(keywords, dict):
        modifier_key = next(iter(keywords))
        if modifier_key.startswith("|"):
            modifiers = [m for m in modifier_key.split("|") if m]
            keywords = keywords[modifier_key]
    if isinstance(keywords, str):
        keywords = [keywords]
    if not keywords:
        raise ValueError("at least one keyword is required")

    hle = data.get("high_level_event")
    label = (hle or {}).get("type") if isinstance(hle, dict) else None
    if not label:
        label = data.get("title") or path.stem

    use_regex = "re" in modifiers
    patterns = []
    for kw in keywords:
        kw = str(kw)
        if use_regex:
            try:
                patterns.append(re.compile(kw))
            except re.error as e:
                print(f"  ! Invalid regex in {path.name}: `{kw}`: {e}")
                patterns.append(None)  # never matches, like SigmaDFT
        else:
            patterns.append(kw)

    return {
        "title": data.get("title", path.stem),
        "label": str(label),
        "patterns": patterns,
        "use_regex": use_regex,
        "require_all": "all" in modifiers,
    }


def rule_matches(rule, text: str) -> bool:
    if rule["use_regex"]:
        results = (p is not None and p.search(text) is not None for p in rule["patterns"])
    else:
        results = (p in text for p in rule["patterns"])
    return all(results) if rule["require_all"] else any(results)


def event_text(row):
    """Same text SigmaDFT matches against: type + evidence + plugin."""
    r = row + [""] * (8 - len(row))
    return f"{r[1]}-{r[2]} {r[4]} {r[2]}-{r[3]}-{r[5]}"


def main():
    ap = argparse.ArgumentParser(description="Label a Plaso CSV timeline with atlas rules (SigmaDFT matching).")
    ap.add_argument("-i", "--input", required=True, help="input Plaso CSV")
    ap.add_argument("-o", "--output", required=True, help="output labeled CSV")
    ap.add_argument("-r", "--rules", default=str(DEFAULT_RULES_DIR),
                    help=f"rules directory (default: {DEFAULT_RULES_DIR})")
    args = ap.parse_args()

    start = time.time()
    rules_dir = Path(args.rules)
    if not rules_dir.is_dir():
        sys.exit(f"Rules directory not found: {rules_dir}")

    rules = []
    for path in discover_rules(rules_dir):
        try:
            rules.append(load_rule(path))
            print(f"  ✓ Loaded rule: {path.relative_to(rules_dir)}")
        except Exception as e:
            print(f"  ✗ Skipped {path.relative_to(rules_dir)}: {e}")
    print(f"Loaded {len(rules)} rules")

    csv.field_size_limit(1000000)
    counts = {r["title"]: 0 for r in rules}
    total = labeled = 0

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.input, "r", encoding="utf-8", newline="") as fin, \
         open(args.output, "w", encoding="utf-8", newline="") as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)

        header = next(reader, None)
        if header is None:
            sys.exit("Input CSV is empty")
        writer.writerow(header + [LABEL_COLUMN])

        for row in reader:
            total += 1
            text = event_text(row)
            labels = []
            for rule in rules:
                if rule_matches(rule, text):
                    counts[rule["title"]] += 1
                    if rule["label"] not in labels:
                        labels.append(rule["label"])
            if labels:
                labeled += 1
            writer.writerow(row + [LABEL_SEPARATOR.join(labels)])

    print("Matches per rule:")
    for title, n in counts.items():
        if n:
            print(f"  {n:>7}  {title}")
    print(f"Rows: {total}, labeled: {labeled}, unlabeled: {total - labeled}")
    print(f"Output: {args.output} ({time.time() - start:.3f} s)")


if __name__ == "__main__":
    main()
