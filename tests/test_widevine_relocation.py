# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0

"""Public synthetic fixtures run through the selected extract-utils implementation.

Put the selected tools/extract-utils on PYTHONPATH. No private capture is needed.
"""
import contextlib
import hashlib
import io
from pathlib import Path
import runpy
import tempfile
import unittest

from extract_utils.file import File
from extract_utils.module import PinnedFileProcessResult

ROOT = Path(__file__).resolve().parents[1]
MODULE = runpy.run_path(str(ROOT / "extract-files.py"))["module"]
RC = "vendor/etc/init/android.hardware.drm@1.2-service.widevine.rc"
BINARY = "android.hardware.drm@1.2-service.widevine"
MIGRATION = (
    "on property:init.svc.mediadrm=running\n"
    "    mkdir /data/vendor/mediadrm 0770 media mediadrm\n"
    "    start vendor.move_data_sh\n\n"
    "service vendor.move_data_sh /system/bin/move_widevine_data.sh\n"
    "    disabled\n    oneshot\n\n"
)
ORIGINAL = (
    f"service vendor.drm-widevine-hal-1-2 /vendor/preavs/bin/hw/{BINARY}\n"
    "    class hal\n"
    "    setenv LD_LIBRARY_PATH /vendor/preavs/lib\n"
).encode()
EXPECTED = (
    f"service vendor.drm-widevine-hal-1-2 /vendor/bin/hw/{BINARY}\n"
    "    class hal\n"
    "    setenv LD_LIBRARY_PATH /vendor/lib\n"
).encode()


class WidevineRelocationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "fixture.rc"

    def apply(self, data):
        self.path.write_bytes(data)
        MODULE.fixup_module_file(File(RC), str(self.path))
        return self.path.read_bytes()

    def test_original_paths_relocate_once_and_preserve_migration(self):
        for newline in (b"\n", b"\r\n"):
            with self.subTest(newline=newline):
                original = (MIGRATION.encode() + ORIGINAL).replace(b"\n", newline)
                expected = (MIGRATION.encode() + EXPECTED).replace(b"\n", newline)
                actual = self.apply(original)
                self.assertEqual(actual, expected)
                self.assertNotIn(b"/vendor/vendor", actual)
                self.assertEqual(actual.count(b"/vendor/bin/hw/"), 1)
                self.assertEqual(actual.count(b"/vendor/lib"), 1)

    def test_repeated_fixup_and_already_relocated_input_are_unchanged(self):
        self.assertEqual(self.apply(self.apply(ORIGINAL)), EXPECTED)
        self.assertEqual(self.apply(EXPECTED), EXPECTED)

    def test_comments_other_directives_and_longer_paths_are_not_rewritten(self):
        unrelated = (
            "# preavs must remain literal\n"
            f"# service vendor.drm-widevine-hal-1-2 /vendor/preavs/bin/hw/{BINARY}\n"
            f"service unrelated /vendor/preavs/bin/hw/{BINARY}\n"
            f"service vendor.drm-widevine-hal-1-2 /vendor/preavs/bin/hw/{BINARY}.other\n"
            "    setenv OTHER_PATH /vendor/preavs/lib\n"
            "    setenv LD_LIBRARY_PATH /vendor/preavs/lib64\n"
            "    setenv LD_LIBRARY_PATH /vendor/preavs/library\n"
            "    setprop vendor.preavs.state preavs\n"
        ).encode()
        self.assertEqual(self.apply(unrelated + ORIGINAL), unrelated + EXPECTED)

    def pinned_fixture(self):
        before = hashlib.sha1(ORIGINAL).hexdigest()
        after = hashlib.sha1(EXPECTED).hexdigest()
        return File(f"{RC}|{before}|{after}")

    def process_pinned(self, data, restored):
        self.path.write_bytes(data)
        with contextlib.redirect_stdout(io.StringIO()):
            result = MODULE.process_pinned_file(
                self.pinned_fixture(), str(self.path), restored=restored)
        return result, self.path.read_bytes()

    def test_selected_pinned_extraction_accepts_original_and_corrected_backup(self):
        for data, restored in ((ORIGINAL, False), (EXPECTED, True)):
            with self.subTest(restored=restored):
                result, actual = self.process_pinned(data, restored)
                self.assertEqual(result, PinnedFileProcessResult.MATCH)
                self.assertEqual(actual, EXPECTED)

    def test_selected_pinned_extraction_rejects_old_malformed_backup(self):
        old_output = ORIGINAL.replace(b"preavs", b"vendor")
        result, actual = self.process_pinned(old_output, restored=True)
        self.assertEqual(result, PinnedFileProcessResult.MISMATCH)
        self.assertEqual(actual, old_output)

    def test_inventory_destinations_agree_with_service_and_library_paths(self):
        files = [File(line) for line in (ROOT / "proprietary-files.txt").read_text().splitlines()
                 if line and not line.startswith("#")]
        selected = {file.src: file for file in files}
        self.assertEqual(selected[f"preavs/bin/hw/{BINARY}"].dst,
                         f"vendor/bin/hw/{BINARY}")
        self.assertEqual(selected["preavs/lib/libwvhidl.so"].dst,
                         "vendor/lib/libwvhidl.so")
        self.assertIsNotNone(selected[RC].hash)
        self.assertIsNotNone(selected[RC].fixup_hash)


if __name__ == "__main__":
    unittest.main()
