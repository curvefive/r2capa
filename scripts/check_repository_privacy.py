#!/usr/bin/env python3
"""Reject common personal data and credential artifacts before publication."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WINDOWS_SEPARATOR = re.escape(b"\\")
USER_HOME_PATTERN = (
    rb"(?:/"
    + b"Users/|/home/|[A-Za-z]:"
    + WINDOWS_SEPARATOR
    + b"Users"
    + WINDOWS_SEPARATOR
    + rb")[A-Za-z0-9._-]+"
)

CONTENT_RULES = {
    "absolute user home path": re.compile(USER_HOME_PATTERN, re.IGNORECASE),
    "private temporary path": re.compile(rb"/private/var/folders/[A-Za-z0-9_./-]+"),
    "email address": re.compile(
        rb"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+",
        re.IGNORECASE,
    ),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "AWS access key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(rb"\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b"),
}

FORBIDDEN_NAMES = (
    ".DS_Store",
    ".env",
    ".idea",
    ".vscode",
)
FORBIDDEN_SUFFIXES = (".key", ".log", ".p12", ".pem", ".pfx", ".swp")
SAFE_ARCHIVE_OWNERS = {"", "daemon", "root"}


def publication_files() -> list[Path]:
    """Return tracked and untracked files that are not excluded by Git."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / Path(name.decode("utf-8")) for name in result.stdout.split(b"\0") if name]


def inspect_content(name: str, content: bytes, findings: list[str]) -> None:
    for label, pattern in CONTENT_RULES.items():
        if pattern.search(content):
            findings.append(f"{name}: {label}")


def inspect_distribution(path: Path, findings: list[str]) -> None:
    if path.name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        with tarfile.open(path, "r:*") as archive:
            for tar_member in archive.getmembers():
                if tar_member.uname not in SAFE_ARCHIVE_OWNERS:
                    findings.append(f"{path}:{tar_member.name}: identifying archive owner")
                if tar_member.gname not in SAFE_ARCHIVE_OWNERS:
                    findings.append(f"{path}:{tar_member.name}: identifying archive group")
                if tar_member.isfile() and (stream := archive.extractfile(tar_member)) is not None:
                    inspect_content(f"{path}:{tar_member.name}", stream.read(), findings)
        return

    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            for zip_member in archive.infolist():
                if not zip_member.is_dir():
                    inspect_content(
                        f"{path}:{zip_member.filename}", archive.read(zip_member), findings
                    )
        return

    findings.append(f"{path}: unsupported distribution format")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distributions", nargs="*", type=Path, default=[])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings: list[str] = []
    files = publication_files()
    for path in files:
        relative = path.relative_to(ROOT)
        parts = set(relative.parts)
        if parts.intersection(FORBIDDEN_NAMES) or relative.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append(f"{relative}: local or sensitive artifact")
            continue

        try:
            inspect_content(str(relative), path.read_bytes(), findings)
        except OSError as error:
            findings.append(f"{relative}: cannot inspect ({error})")

    for distribution in args.distributions:
        try:
            inspect_distribution(distribution, findings)
        except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
            findings.append(f"{distribution}: cannot inspect ({error})")

    if findings:
        print("Repository privacy check failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1

    suffix = f", {len(args.distributions)} distributions inspected" if args.distributions else ""
    print(f"Repository privacy check passed ({len(files)} files inspected{suffix})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
