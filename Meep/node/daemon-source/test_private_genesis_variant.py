#!/usr/bin/env python3
"""Offline source-transform and refusal tests for the private variant tool."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import private_genesis_variant as variant

from private_genesis_variant import (
    OLD_GENESIS_TS,
    OLD_NETWORK_PREFIX,
    VariantError,
    check_input,
    create_variant,
    format_network_id,
    network_ids,
    transformed_files,
)


def git(root, *args):
    proc = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


def fixture_repository(root):
    source = Path(root) / "canonical"
    (source / "src/hardforks").mkdir(parents=True)
    config, forks = fixtures()
    (source / variant.CONFIG_REL).write_bytes(config)
    (source / variant.FORKS_REL).write_bytes(forks)
    # This test asserts byte-for-byte clone identity. The machine's Git
    # core.autocrlf setting must not silently rewrite the synthetic fixture.
    (source / ".gitattributes").write_bytes(b"* -text\n")
    git(source, "init", "--quiet")
    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "add", "--", ".gitattributes", "src/cryptonote_config.h", "src/hardforks/hardforks.cpp")
    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "--quiet", "-m", "synthetic canonical fixture")
    return source, config, forks


def fixtures():
    config = (
        f"#define MEEPCOIN_GENESIS_TIMESTAMP              {OLD_GENESIS_TS}ULL\n"
        + "\n".join(
            format_network_id(OLD_NETWORK_PREFIX + bytes([index])) for index in range(3)
        )
        + "\n"
    ).encode("utf-8")
    forks = (f"{{ 16, 0, 0, {OLD_GENESIS_TS} }},\n" * 3).encode("utf-8")
    return config, forks


class VariantTests(unittest.TestCase):
    def test_replaces_exactly_the_declared_anchors(self):
        config, forks = fixtures()
        changed, ids = transformed_files(config, forks, 1800000000, "fresh-pair-1")
        cfg = changed[Path("src/cryptonote_config.h")].decode()
        hfs = changed[Path("src/hardforks/hardforks.cpp")].decode()
        self.assertIn("MEEPCOIN_GENESIS_TIMESTAMP              1800000000ULL", cfg)
        self.assertEqual(hfs.count("{ 16, 0, 0, 1800000000 },"), 3)
        self.assertNotIn(str(OLD_GENESIS_TS), cfg + hfs)
        self.assertEqual(len(set(ids)), 3)
        for value in ids:
            self.assertEqual(len(value), 16)
            self.assertNotEqual(value[:15], OLD_NETWORK_PREFIX)
            self.assertIn(format_network_id(value), cfg)

    def test_network_identity_is_deterministic_and_variant_specific(self):
        first = network_ids(1800000000, "fresh-pair-1")
        self.assertEqual(first, network_ids(1800000000, "fresh-pair-1"))
        self.assertNotEqual(first, network_ids(1800000001, "fresh-pair-1"))
        self.assertNotEqual(first, network_ids(1800000000, "fresh-pair-2"))

    def test_missing_or_extra_anchor_refuses_before_writing(self):
        config, forks = fixtures()
        for bad_config in (config.replace(b"1785283200ULL", b"0ULL"), config + config):
            with self.assertRaises(VariantError):
                transformed_files(bad_config, forks, 1800000000, "fresh-pair-1")
        for bad_forks in (forks.replace(b"1785283200", b"0", 1), forks + forks):
            with self.assertRaises(VariantError):
                transformed_files(config, bad_forks, 1800000000, "fresh-pair-1")

    def test_existing_destination_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "source"
            dest = Path(root) / "dest"
            source.mkdir()
            dest.mkdir()
            with self.assertRaisesRegex(VariantError, "destination must not exist"):
                check_input(source, dest)

    def test_destination_inside_source_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "source"
            source.mkdir()
            with self.assertRaisesRegex(VariantError, "outside the canonical source"):
                check_input(source, source / "nested")

    def test_end_to_end_manifest_is_the_written_source_tree(self):
        with tempfile.TemporaryDirectory() as root:
            source, config, forks = fixture_repository(root)
            canonical_tree = git(source, "rev-parse", "HEAD^{tree}")
            destination = Path(root) / "variant"
            with patch.object(variant, "BASE_TREE", canonical_tree):
                reported = create_variant(source, destination, 1800000000, "synthetic-pair")
            copied = destination / "src"
            on_disk = json.loads((destination / "VARIANT_SOURCE_MANIFEST.json").read_text())
            self.assertEqual(reported, on_disk)
            self.assertEqual(on_disk["canonical_source_tree"], canonical_tree)
            self.assertNotEqual(on_disk["variant_source_tree"], canonical_tree)
            self.assertEqual(git(copied, "write-tree"), canonical_tree)
            self.assertEqual(git(copied, "diff", "--name-only").splitlines(), [
                "src/cryptonote_config.h", "src/hardforks/hardforks.cpp"
            ])
            git(copied, "add", "--", "src/cryptonote_config.h", "src/hardforks/hardforks.cpp")
            self.assertEqual(git(copied, "write-tree"), on_disk["variant_source_tree"])
            self.assertEqual((source / variant.CONFIG_REL).read_bytes(), config)
            self.assertEqual((source / variant.FORKS_REL).read_bytes(), forks)
            self.assertEqual(git(source, "status", "--porcelain"), "")
            for rel, hashes in on_disk["changed_files"].items():
                self.assertEqual(
                    variant.digest((copied / rel).read_bytes()), hashes["after_sha256"]
                )

    def test_dirty_or_wrong_tree_refuses_without_creating_destination(self):
        with tempfile.TemporaryDirectory() as root:
            source, _, _ = fixture_repository(root)
            destination = Path(root) / "variant"
            with self.assertRaisesRegex(VariantError, "locked canonical tree"):
                create_variant(source, destination, 1800000000, "synthetic-pair")
            self.assertFalse(destination.exists())
            canonical_tree = git(source, "rev-parse", "HEAD^{tree}")
            (source / variant.CONFIG_REL).write_bytes(b"dirty\n")
            with patch.object(variant, "BASE_TREE", canonical_tree):
                with self.assertRaisesRegex(VariantError, "not clean"):
                    create_variant(source, destination, 1800000000, "synthetic-pair")
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
