#!/usr/bin/env python3
"""Verify an archive checksum, then run its freshly extracted executable."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import zipfile

archive, sums = map(Path, sys.argv[1:3])
version = (Path(__file__).resolve().parents[1] / "action-version.txt").read_text().strip()
expected = [row.split()[0] for row in sums.read_text().splitlines() if len(row.split()) == 2 and row.split()[1] == archive.name]
if len(expected) != 1 or hashlib.sha256(archive.read_bytes()).hexdigest() != expected[0]:
    raise SystemExit("Release checksum mismatch")
name = "leakguard.exe" if archive.suffix == ".zip" else "leakguard"
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            if bundle.namelist() != [name]:
                raise SystemExit("Unexpected ZIP members")
            payload = bundle.read(name)
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            if bundle.getnames() != [name] or not bundle.getmember(name).isfile():
                raise SystemExit("Unexpected tar members")
            payload = bundle.extractfile(name).read()
    binary = root / name
    binary.write_bytes(payload)
    binary.chmod(0o755)
    result = subprocess.run([str(binary), "--version"], capture_output=True, text=True)
    if result.returncode or result.stdout.strip() != f"leakguard {version}":
        raise SystemExit("Extracted binary version mismatch")
    canary = "ghp_" + "Ab3xY9kLm2NqR7sTu4VwZ8cDe5FgH6jIp0KlMnOp"
    (root / "clean.txt").write_text("safe\n")
    (root / "secret.txt").write_text("Authorization: Bearer " + canary)
    for path, code in [("clean.txt", 0), ("secret.txt", 1), ("missing.txt", 2)]:
        result = subprocess.run([str(binary), "scan", str(root / path)], capture_output=True, text=True)
        if result.returncode != code or canary in result.stdout + result.stderr:
            raise SystemExit("Extracted binary scan/redaction smoke failed")
print(f"Archive checksum, version, exit 0/1/2 and redaction: PASS ({archive.name})")
