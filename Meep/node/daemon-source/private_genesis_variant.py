#!/usr/bin/env python3
"""Create a source-only private fresh-genesis variant of the locked daemon.

This tool never edits its input. It clones a clean canonical reconstruction into
a *new* destination, changes only the compiled genesis time, the three private
network IDs, and their height-zero hardfork times, then records the exact tree
and diff. It does not build, test, launch, or authorize a network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


BASE_TREE = "9ce29e2c482910d911d8d3277bf7de4e85fd679b"
OLD_GENESIS_TS = 1785283200
CONFIG_REL = Path("src/cryptonote_config.h")
FORKS_REL = Path("src/hardforks/hardforks.cpp")
OLD_NETWORK_PREFIX = bytes.fromhex("4d454550c01a4de7b00b5eed1abe11")
VARIANT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class VariantError(ValueError):
    pass


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    if proc.returncode:
        raise VariantError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_replace(text: str, old: str, new: str, count: int, label: str) -> str:
    actual = text.count(old)
    if actual != count:
        raise VariantError(f"{label}: expected {count} canonical anchors, found {actual}")
    return text.replace(old, new)


def network_ids(genesis_ts: int, variant_id: str) -> tuple[bytes, bytes, bytes]:
    payload = (
        f"meepcoin-private-genesis/1\n{BASE_TREE}\n{genesis_ts}\n{variant_id}\n"
    ).encode("ascii")
    prefix = hashlib.sha256(payload).digest()[:15]
    if prefix == OLD_NETWORK_PREFIX:
        raise VariantError("derived network ID collides with the canonical prefix")
    return tuple(prefix + bytes([index]) for index in range(3))


def format_network_id(value: bytes) -> str:
    return ", ".join(f"0x{part:02X}" for part in value)


def transformed_files(
    config: bytes, forks: bytes, genesis_ts: int, variant_id: str
) -> tuple[dict[Path, bytes], tuple[bytes, bytes, bytes]]:
    try:
        cfg = config.decode("utf-8")
        hfs = forks.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VariantError("canonical source must be UTF-8") from exc

    cfg = checked_replace(
        cfg,
        f"MEEPCOIN_GENESIS_TIMESTAMP              {OLD_GENESIS_TS}ULL",
        f"MEEPCOIN_GENESIS_TIMESTAMP              {genesis_ts}ULL",
        1,
        "compiled genesis timestamp",
    )
    identities = network_ids(genesis_ts, variant_id)
    for index, value in enumerate(identities):
        old = format_network_id(OLD_NETWORK_PREFIX + bytes([index]))
        cfg = checked_replace(cfg, old, format_network_id(value), 1, f"network ID {index}")

    hfs = checked_replace(
        hfs,
        f"{{ 16, 0, 0, {OLD_GENESIS_TS} }},",
        f"{{ 16, 0, 0, {genesis_ts} }},",
        3,
        "height-zero hardfork schedule",
    )
    return {CONFIG_REL: cfg.encode("utf-8"), FORKS_REL: hfs.encode("utf-8")}, identities


def check_input(source: Path, destination: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        raise VariantError("source must be a real directory")
    if destination.exists() or destination.is_symlink():
        raise VariantError("destination must not exist")
    source_real = source.resolve(strict=True)
    destination_real = destination.resolve(strict=False)
    if source_real == destination_real or source_real in destination_real.parents:
        raise VariantError("destination must be outside the canonical source")
    if destination_real in source_real.parents:
        raise VariantError("destination must not contain the canonical source")
    if git(source, "rev-parse", "HEAD^{tree}") != BASE_TREE:
        raise VariantError("source HEAD is not the locked canonical tree")
    if git(source, "status", "--porcelain"):
        raise VariantError("source is not clean")


def create_variant(
    source: Path, destination: Path, genesis_ts: int, variant_id: str
) -> dict[str, object]:
    if not isinstance(genesis_ts, int) or not (OLD_GENESIS_TS < genesis_ts < 2**63):
        raise VariantError("genesis timestamp must be an integer after the canonical epoch")
    if not VARIANT_ID_RE.fullmatch(variant_id):
        raise VariantError("variant ID must be lowercase ASCII, 1-64 chars, starting with a letter")
    check_input(source, destination)
    source_head = git(source, "rev-parse", "HEAD")

    # Validate every replacement against the input before creating a destination.
    original = {rel: (source / rel).read_bytes() for rel in (CONFIG_REL, FORKS_REL)}
    changed, identities = transformed_files(
        original[CONFIG_REL], original[FORKS_REL], genesis_ts, variant_id
    )

    destination.mkdir(parents=True, exist_ok=False)
    copied = destination / "src"
    try:
        proc = subprocess.run(
            ["git", "clone", "--quiet", "--local", "--no-hardlinks", str(source), str(copied)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode:
            raise VariantError(f"clone failed: {proc.stderr.strip()}")
        git(copied, "checkout", "--detach", "--quiet", source_head)
        if git(copied, "rev-parse", "HEAD^{tree}") != BASE_TREE or git(copied, "status", "--porcelain"):
            raise VariantError("copied source differs from the canonical tree")
        for rel, data in changed.items():
            target = copied / rel
            if target.read_bytes() != original[rel]:
                raise VariantError(f"copied source moved during clone: {rel}")
            target.write_bytes(data)
            if target.read_bytes() != data:
                raise VariantError(f"variant write did not preserve intended bytes: {rel}")
        names = git(copied, "diff", "--name-only").splitlines()
        expected = sorted(str(path).replace("\\", "/") for path in changed)
        if sorted(names) != expected:
            raise VariantError(f"variant changed unexpected paths: {names}")
        # Hash the exact on-disk source without making a commit or changing the lock.
        git(copied, "add", "--", *expected)
        variant_tree = git(copied, "write-tree")
        git(copied, "reset", "--quiet", "--", *expected)
        manifest: dict[str, object] = {
            "schema": "meepcoin-private-genesis-source-variant/1",
            "status": "SOURCE_ONLY_NOT_BUILT_NOT_TESTED_NO_LAUNCH",
            "variant_id": variant_id,
            "genesis_timestamp": genesis_ts,
            "canonical_source_tree": BASE_TREE,
            "variant_source_tree": variant_tree,
            "network_ids": {name: value.hex() for name, value in zip(
                ("mainnet", "testnet", "stagenet"), identities
            )},
            "changed_files": {
                str(rel).replace("\\", "/"): {
                    "before_sha256": digest(original[rel]),
                    "after_sha256": digest(changed[rel]),
                }
                for rel in (CONFIG_REL, FORKS_REL)
            },
            "known_inapplicable_tests": [
                "meepcoin-runtime-quarantine-test: old genesis IDs and block blobs",
                "meepcoin-runtime-quarantine-guards: old timestamp literal",
                "old genesis-specific block vectors and simulations",
            ],
            "warning": "Separate source variant only. No binary, test result, genesis hash, or live authorization.",
        }
        (destination / "VARIANT_SOURCE_MANIFEST.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return manifest
    except Exception:
        # Preserve an incomplete destination for inspection, never reuse it silently.
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="clean locked reconstruction")
    parser.add_argument("--dest", type=Path, required=True, help="new directory outside source")
    parser.add_argument("--genesis-ts", type=int, required=True, help="compiled Unix epoch seconds")
    parser.add_argument("--variant-id", required=True, help="lowercase private variant label")
    args = parser.parse_args(argv)
    try:
        manifest = create_variant(args.source, args.dest, args.genesis_ts, args.variant_id)
    except (VariantError, OSError) as exc:
        print(f"private genesis variant REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
