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

class Attempt10FixupTests(unittest.TestCase):
    def _load(self, rel):
        spec = importlib.util.spec_from_file_location(rel.replace("/", "_"), ROOT / rel)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_camera_metadata_undef_rejects_unknown_sha_and_clears_defined_targets(self):
        import struct
        mod = self._load("fixups/camera_metadata_undef.py")
        dynstr = b"\x00camera_metadata_section_bounds\x00camera_metadata_section_names\x00other\x00"
        dynsym = bytearray()
        dynsym += struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
        dynsym += struct.pack("<IBBHQQ", 1, 0x11, 0, 11, 0x2d540, 256)
        dynsym += struct.pack("<IBBHQQ", 32, 0x11, 0, 11, 0x2d440, 256)
        dynsym += struct.pack("<IBBHQQ", 62, 0x12, 0, 9, 0x13000, 16)
        sh_off = 64 + len(dynstr) + len(dynsym)
        ehdr = bytearray(64)
        ehdr[:6] = b"\x7fELF\x02\x01"
        ehdr[18:20] = b"\xb7\x00"
        struct.pack_into("<Q", ehdr, 40, sh_off)
        struct.pack_into("<HH", ehdr, 58, 64, 3)
        sh0 = bytes(64)
        sh1 = struct.pack("<IIQQQQIIQQ", 0, 3, 2, 0, 64, len(dynstr), 0, 0, 1, 0)
        sh2 = struct.pack("<IIQQQQIIQQ", 0, 11, 2, 0, 64 + len(dynstr), len(dynsym), 1, 1, 8, 24)
        blob = bytes(ehdr) + dynstr + bytes(dynsym) + sh0 + sh1 + sh2
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            mod.patch_camera_metadata_undef(blob)
        with mock.patch.object(mod, "EXPECTED_SHA256", hashlib.sha256(blob).hexdigest()):
            out = mod.patch_camera_metadata_undef(blob)
        for idx, exp in [(1, (0, 0, 0)), (2, (0, 0, 0)), (3, (9, 0x13000, 16))]:
            _, _, _, shndx, val, sz = struct.unpack_from("<IBBHQQ", out, 64 + len(dynstr) + idx * 24)
            self.assertEqual((shndx, val, sz), exp)

    def test_libril_voicereg_patches_both_arches_and_rejects_unknown_sha(self):
        mod = self._load("fixups/libril_voicereg_v12.py")
        hdr64 = bytearray(0x752C8 + 64)
        hdr64[:6] = b"\x7fELF\x02\x01"
        hdr64[18:20] = b"\xb7\x00"
        hdr64[0x752C8 : 0x752C8 + len(mod.WINDOW_64_OLD)] = mod.WINDOW_64_OLD
        b64 = bytes(hdr64)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            mod.patch_libril_voicereg(b"\x7fELF" + b"\x00" * 60)
        with mock.patch.object(mod, "EXPECTED_SHA256_64", hashlib.sha256(b64).hexdigest()):
            out64 = mod.patch_libril_voicereg(b64)
        self.assertEqual(out64[0x752C8 : 0x752C8 + len(mod.WINDOW_64_NEW)], mod.WINDOW_64_NEW)

        hdr32 = bytearray(0x4B570 + 64)
        hdr32[:6] = b"\x7fELF\x01\x01"
        hdr32[18:20] = b"\x28\x00"
        hdr32[0x4B570 : 0x4B570 + len(mod.WINDOW_32_OLD)] = mod.WINDOW_32_OLD
        b32 = bytes(hdr32)
        with mock.patch.object(mod, "EXPECTED_SHA256_32", hashlib.sha256(b32).hexdigest()):
            out32 = mod.patch_libril_voicereg(b32)
        self.assertEqual(out32[0x4B570 : 0x4B570 + len(mod.WINDOW_32_NEW)], mod.WINDOW_32_NEW)

class Attempt12HwImsFixupTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("build_hwims_apk", ROOT / "fixups/build_hwims_apk.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_hwims_entries_are_pinned_as_soong_packages(self):
        from extract_utils.file import FileList

        fl = FileList()
        fl.add_from_file(str(ROOT / "proprietary-files.txt"))
        pkg_by_src = {f.src: f for f in fl.package_files}
        self.assertIn("system/app/HwIms/HwIms.apk", pkg_by_src)
        self.assertIn("system/etc/noticeFile/HwIms.html", pkg_by_src)
        apk = pkg_by_src["system/app/HwIms/HwIms.apk"]
        html = pkg_by_src["system/etc/noticeFile/HwIms.html"]
        self.assertFalse(apk.is_package)  # .apk is auto-packaged by FileList without '-'
        self.assertEqual(apk.hash, "867bc054b6d71a8cef718830cec65a41d6ba069d")
        self.assertEqual(apk.fixup_hash, "cd9927f49de6d204f6af762e0a1613d935ad6ccc")
        self.assertTrue(html.is_package)
        self.assertEqual(html.hash, "adb1ae32a5c562d488dadf0c1a962940e85c9e1a")

    def test_verify_hwims_inputs_rejects_missing_or_tampered_inputs(self):
        mod = self._load()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            with self.assertRaises(FileNotFoundError):
                mod.verify_hwims_inputs(tdp, {"app/HwIms/HwIms.apk": "0" * 64})
            target = tdp / "app/HwIms/HwIms.apk"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                mod.verify_hwims_inputs(tdp, {"app/HwIms/HwIms.apk": "0" * 64})
            mod.verify_hwims_inputs(tdp, {"app/HwIms/HwIms.apk": hashlib.sha256(b"tampered").hexdigest()})

    def test_replace_exact_rejects_zero_or_duplicate_matches(self):
        mod = self._load()
        with self.assertRaisesRegex(ValueError, "expected 1"):
            mod._replace_exact("abc", "xyz", "123", 1, "missing")
        with self.assertRaisesRegex(ValueError, "expected 1"):
            mod._replace_exact("xyz xyz", "xyz", "123", 1, "dup")
        self.assertEqual(mod._replace_exact("a xyz b", "xyz", "123", 1, "ok"), "a 123 b")


class Attempt13MapconFixupTests(unittest.TestCase):
    def _load(self):
        spec = importlib.util.spec_from_file_location("build_mapcon_apk", ROOT / "fixups/build_mapcon_apk.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_mapcon_and_vowifi_entries_are_pinned_in_file_list(self):
        from extract_utils.file import FileList

        fl = FileList()
        fl.add_from_file(str(ROOT / "proprietary-files.txt"))
        pkg_by_src = {f.src: f for f in fl.package_files}
        all_by_src = {f.src: f for f in fl.all_files}
        self.assertIn("system/app/Mapcon/Mapcon.apk", pkg_by_src)
        mapcon = pkg_by_src["system/app/Mapcon/Mapcon.apk"]
        self.assertEqual(mapcon.hash, "f34bc5fd3ffbbc96b4bd9362ae5569858ff81f20")
        self.assertEqual(mapcon.fixup_hash, "a243cfb8995a56e21d6cdc9b1930e428ceeb938a")
        for bin_or_lib in (
            "vendor/bin/iked",
            "vendor/bin/hinetmanager",
            "vendor/bin/hivwserver",
            "vendor/lib64/libracoon2.so",
            "vendor/lib64/vendor.huawei.hardware.iked@1.0.so",
            "vendor/lib64/vendor.huawei.hardware.hinetmanager@1.0.so",
        ):
            self.assertIn(bin_or_lib, all_by_src)
            self.assertIsNotNone(all_by_src[bin_or_lib].hash)

    def test_verify_mapcon_inputs_rejects_missing_or_tampered_inputs(self):
        mod = self._load()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            with self.assertRaises(FileNotFoundError):
                mod.verify_mapcon_inputs(tdp, {"app/Mapcon/Mapcon.apk": "0" * 64})
            target = tdp / "app/Mapcon/Mapcon.apk"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                mod.verify_mapcon_inputs(tdp, {"app/Mapcon/Mapcon.apk": "0" * 64})
            mod.verify_mapcon_inputs(
                tdp, {"app/Mapcon/Mapcon.apk": hashlib.sha256(b"tampered").hexdigest()}
            )

if __name__ == "__main__":
    unittest.main()
