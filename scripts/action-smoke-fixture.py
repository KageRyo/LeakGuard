#!/usr/bin/env python3
"""Prepare and verify controlled fixtures for the published consumer Action."""
import json
import os
from pathlib import Path
import sys

root = Path(".superpowers/action-smoke")
canary = "ghp_" + "Ab3xY9kLm2NqR7sTu4VwZ8cDe5FgH6jIp0KlMnOp"
if sys.argv[1] == "seed":
    root.mkdir(parents=True, exist_ok=True)
    (root / "clean.txt").write_text("safe\n")
    (root / "secret.log").write_text("Authorization: Bearer " + canary)
elif sys.argv[1] == "check":
    clean_text = (root / "clean.json").read_text()
    secret_text = (root / "finding.sarif").read_text()
    clean, secret = json.loads(clean_text), json.loads(secret_text)  # leakguard:allow detector false positive on a code assignment
    assert clean["scanned_files"] == 1 and clean["findings"] == []
    assert os.environ["FINDING_OUTCOME"] == "failure"
    results = secret["runs"][0]["results"]
    assert len(results) == 1 and results[0]["ruleId"] == "github-token"
    assert results[0]["level"] == "error" and results[0]["properties"]["confidence"] == "high"
    assert canary not in clean_text + secret_text
    print("Published Action clean/finding exits and redacted JSON/SARIF: PASS")
else:
    raise SystemExit("Unknown smoke phase")
