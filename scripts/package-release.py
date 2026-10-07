#!/usr/bin/env python3
"""Package a built target. Publication is handled separately by the release job."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile

root = Path(__file__).resolve().parents[1]
version = re.search(r'^version = "([^"]+)"', (root / "Cargo.toml").read_text(), re.M).group(1)
if (root / "action-version.txt").read_text().strip() != version:
    raise SystemExit("Action/package version mismatch")
if os.environ.get("RELEASE_TAG") and os.environ["RELEASE_TAG"] != f"v{version}":
    raise SystemExit("Tag/package version mismatch")
target = os.environ["RELEASE_TARGET"]
if target not in {"x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "aarch64-apple-darwin"}:
    raise SystemExit("Unsupported release target")
name = "leakguard.exe" if "windows" in target else "leakguard"
binary = root / "target" / target / "release" / name
# Cross-built macOS executables cannot run on an x86_64 packaging host.
if "apple" not in target:
    result = subprocess.run([str(binary), "--version"], check=True, capture_output=True, text=True)
    if result.stdout.strip() != f"leakguard {version}":
        raise SystemExit("Binary/package version mismatch")
dist = root / "dist"
dist.mkdir(exist_ok=True)
base = f"leakguard-v{version}-{target}"
if "windows" in target:
    archive = dist / f"{base}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(binary, arcname=name)
else:
    archive = dist / f"{base}.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(binary, arcname=name)
checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
( dist / f"{base}.sha256").write_text(f"{checksum}  {archive.name}\n")
