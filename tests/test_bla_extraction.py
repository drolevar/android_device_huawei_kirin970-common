"""Regressions against the selected extract-utils parser, not a mock grammar."""
from pathlib import Path
import unittest
import importlib.util
import hashlib
import io
import os
import tempfile
from types import SimpleNamespace
from unittest import mock
from extract_utils.file import File, FileArgs

ROOT = Path(__file__).resolve().parents[1]

class BlaExtractionTests(unittest.TestCase):
    def files(self):
        return [File(line.strip()) for line in (ROOT / "proprietary-files.txt").read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]

    def test_selected_extractor_accepts_the_complete_common_list(self):
        self.assertGreater(len(self.files()), 900)

    def test_opaque_xml_is_copied_without_xml_schema_interpretation(self):
        entries = {file.src: file for file in self.files()}
        expected_hashes = {
            "vendor/etc/native_packages.xml": "9c348ade1ef172f5765f74406fdc8fe19cc5d71d",
            "vendor/etc/modemConfig/observe_config_encryt.xml": "fffee4b4317b594bdbb36cfc4d7591218455ce07",
        }
        for name, expected_hash in expected_hashes.items():
            self.assertIn(FileArgs.EXTRACT_ONLY, entries[name].args)
            self.assertNotIn(FileArgs.MAKE_COPY_RULE_ONLY, entries[name].args)
            self.assertEqual(entries[name].hash, expected_hash)

        spec = importlib.util.spec_from_file_location("common_recipe", ROOT / "extract-files.py")
        recipe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recipe)
        ctx = SimpleNamespace(bp_out=io.StringIO(), product_mk_out=io.StringIO())
        recipe.write_opaque_xml_packages(ctx, None)
        bp = ctx.bp_out.getvalue()
        mk = ctx.product_mk_out.getvalue()
        self.assertIn('prebuilt_etc {', bp)
        self.assertNotIn('prebuilt_etc_xml', bp)
        self.assertIn('src: "proprietary/vendor/etc/modemConfig/observe_config_encryt.xml"', bp)
        self.assertIn('sub_dir: "modemConfig"', bp)
        self.assertIn('src: "proprietary/vendor/etc/native_packages.xml"', bp)
        self.assertEqual(bp.count('filename_from_src: true'), 2)
        self.assertEqual(bp.count('soc_specific: true'), 2)
        self.assertNotIn('PRODUCT_COPY_FILES', mk)
        self.assertIn('PRODUCT_PACKAGES +=', mk)
        self.assertIn('observe_config_encryt.xml', mk)
        self.assertIn('native_packages.xml', mk)

    def test_each_declared_fixup_has_a_verified_output_pin(self):
        spec = importlib.util.spec_from_file_location("common_recipe", ROOT / "extract-files.py")
        recipe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recipe)
        changed = [file for file in self.files() if recipe.module.should_fixup_file(file)]
        self.assertGreater(len(changed), 20)
        for file in changed:
            self.assertIsNotNone(file.fixup_hash, file.dst)

class SmartAeGuardTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("smartae", ROOT / "fixups/smartae.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = b"\xb7\x00"
        self.blob = bytes(header) + b"prefix" + bytes.fromhex("9F020AB9") + b"suffix"

    def test_unknown_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.module.patch_smartae(self.blob)

    def test_known_fixture_has_exactly_one_instruction_replaced(self):
        with mock.patch.object(self.module, "EXPECTED_SHA256", hashlib.sha256(self.blob).hexdigest()):
            actual = self.module.patch_smartae(self.blob)
        self.assertEqual(actual, self.blob.replace(bytes.fromhex("9F020AB9"), bytes.fromhex("1F2003D5")))
        self.assertEqual(len(actual), len(self.blob))

    def test_ambiguous_or_missing_matches_are_rejected_even_with_matching_hash(self):
        for blob in (self.blob.replace(bytes.fromhex("9F020AB9"), b"abcd"), self.blob + bytes.fromhex("9F020AB9")):
            with mock.patch.object(self.module, "EXPECTED_SHA256", hashlib.sha256(blob).hexdigest()):
                with self.assertRaisesRegex(ValueError, "exactly one"):
                    self.module.patch_smartae(blob)

if __name__ == "__main__":
    unittest.main()
