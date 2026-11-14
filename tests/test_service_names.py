"""Filesystem naming and exact rc rewrite guards for the three stock services."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import unittest

from extract_utils.file import File, FileArgs
from extract_utils.makefiles import file_stem_package_name
from extract_utils.tools import android_root

ROOT = Path(__file__).resolve().parents[1]


class ServiceNamesTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "fixups/hisi_services.py"
        self.assertTrue(path.is_file(), "guarded service rc fixup is not implemented")
        spec = importlib.util.spec_from_file_location("hisi_services", path)
        self.fixup = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.fixup)

    def test_exact_service_exec_only_rewrite(self):
        old = b"/vendor/bin/hw/example-service"
        data = b"service original_id " + old + b"\n    class hal\n    user system\n"
        expected = data.replace(old, old + b".hisi", 1)
        self.assertEqual(self.fixup.rewrite_exec_path(data, old, old + b".hisi"), expected)

    def test_missing_multiple_and_non_service_paths_are_rejected(self):
        old = b"/vendor/bin/hw/example-service"
        for data in (b"service wrong /other/path\n", b"service a " + old + b"\nservice b " + old + b"\n",
                     b"# " + old + b"\n", b"service a " + old + b".unexpected\n"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.fixup.rewrite_exec_path(data, old, old + b".hisi")

    def test_unknown_or_changed_stock_rc_is_rejected(self):
        for destination, record in self.fixup.SERVICE_RCS.items():
            data = b"service unknown " + record["old_exec"].encode() + b"\n"
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                self.fixup.patch_rc(data, destination)

    def test_selected_parser_installs_each_alias_under_its_unique_name(self):
        files = [File(line) for line in (ROOT / "proprietary-files.txt").read_text().splitlines()
                 if line and not line.startswith("#")]
        for destination, record in self.fixup.SERVICE_RCS.items():
            src = record["old_exec"].lstrip("/")
            binary = next(f for f in files if f.src == src)
            stem, module = file_stem_package_name(binary, can_have_stem=True, any_extension=True)
            self.assertEqual(binary.dst, src + ".hisi")
            self.assertEqual(stem, module)
            self.assertEqual(module, Path(src).name + ".hisi")
            self.assertNotIn(FileArgs.DISABLE_CHECKELF, binary.args)
            self.assertNotIn(FileArgs.DISABLE_DEPS, binary.args)
            rc = next(f for f in files if f.dst == destination)
            self.assertEqual(rc.hash, record["input_sha1"])
            self.assertEqual(rc.fixup_hash, record["output_sha1"])

    def test_new_exec_paths_retain_original_selinux_types(self):
        platform = Path(android_root)
        contexts = [ROOT / "sepolicy/vendor/file_contexts",
                    platform / "hardware/huawei/sepolicy/hisi/vendor/file_contexts",
                    platform / "system/sepolicy/vendor/file_contexts"]
        entries = [line.split() for p in contexts for line in p.read_text().splitlines()
                   if line.strip() and not line.lstrip().startswith("#")]
        for record in self.fixup.SERVICE_RCS.values():
            old, new = record["old_exec"], record["new_exec"]
            before = {parts[1] for parts in entries if re.fullmatch(parts[0], old)}
            after = {parts[1] for parts in entries if re.fullmatch(parts[0], new)}
            expected = {record["exec_context"]}
            self.assertEqual(before, expected)
            self.assertEqual(after, expected)

    def test_measured_bla_rc_replay_when_source_is_supplied(self):
        source = os.environ.get("BLA_ORIGINAL_FILESYSTEMS")
        if not source:
            self.skipTest("set BLA_ORIGINAL_FILESYSTEMS for the private measured inputs")
        for destination, record in self.fixup.SERVICE_RCS.items():
            path = Path(source) / "vendor/etc/init" / (Path(record["old_exec"]).name + ".rc")
            data = path.read_bytes()
            output = self.fixup.patch_rc(data, destination)
            self.assertEqual(hashlib.sha1(output).hexdigest(), record["output_sha1"])
            self.assertEqual(output, data.replace(record["old_exec"].encode(),
                                                  record["new_exec"].encode(), 1))

    def test_generated_replay_stems_and_unchanged_elf_bytes(self):
        source = os.environ.get("BLA_ORIGINAL_FILESYSTEMS")
        output = os.environ.get("BLA_EXTRACTED_VENDOR")
        if not source or not output:
            self.skipTest("set BLA_ORIGINAL_FILESYSTEMS and BLA_EXTRACTED_VENDOR")
        root = Path(output)
        bp = (root / "Android.bp").read_text()
        makefile = (root / "kirin970-common-vendor.mk").read_text()
        for destination, record in self.fixup.SERVICE_RCS.items():
            old, new = record["old_exec"].lstrip("/"), record["new_exec"].lstrip("/")
            module = Path(new).name
            block = re.search(r'(?ms)^cc_prebuilt_binary \{\n(?:(?!^\}).)*?name: "'
                              + re.escape(module) + r'",(?:(?!^\}).)*?^\}', bp)
            self.assertIsNotNone(block, module)
            self.assertIn(f'stem: "{module}"', block.group())
            self.assertIn(f'proprietary/{new}', block.group())
            self.assertNotIn('check_elf_files: false', block.group())
            self.assertIn(f'proprietary/{destination}:$(TARGET_COPY_OUT_VENDOR)/'
                          + destination.removeprefix("vendor/"), makefile)
            self.assertEqual((Path(source) / old).read_bytes(),
                             (root / "proprietary" / new).read_bytes())
            oldrc = "vendor/etc/init/" + Path(old).name + ".rc"
            self.assertEqual(self.fixup.patch_rc((Path(source) / oldrc).read_bytes(), destination),
                             (root / "proprietary" / destination).read_bytes())
            self.assertFalse((root / "proprietary" / old).exists())
            self.assertFalse((root / "proprietary" / oldrc).exists())


if __name__ == "__main__":
    unittest.main()
