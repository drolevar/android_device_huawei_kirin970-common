# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
"""Legacy core-data setup must execute as core init, not vendor_init."""
import pathlib
import re
import shlex
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LEGACY = {"/data/sec_storage_data", "/data/sec_storage_data_users"}


def commands(path):
    trigger = None
    for line in path.read_text().splitlines():
        stripped = line.partition("#")[0].strip()
        if not stripped:
            continue
        if not line[0].isspace():
            trigger = stripped
        else:
            yield trigger, shlex.split(stripped)


class TeeInitOwnershipTests(unittest.TestCase):
    def test_core_action_is_installed_in_auto_imported_system_ext_init(self):
        bp = (ROOT / "init/Android.bp").read_text()
        modules = re.findall(r"prebuilt_etc\s*\{([^}]+)\}", bp, re.DOTALL)
        candidates = [m for m in modules if 'name: "init.tee.core.rc"' in m]
        self.assertEqual(len(candidates), 1)
        module = candidates[0]
        self.assertIn('system_ext_specific: true', module)
        self.assertIn('sub_dir: "init"', module)
        self.assertIn('src: "init.tee.core.rc"', module)
        self.assertNotRegex(module, r"(?:vendor|soc_specific|device_specific):\s*true")
        self.assertIn("init.tee.core.rc", (ROOT / "common.mk").read_text())

    def test_legacy_directories_are_created_and_relabelled_only_by_core_init(self):
        core = ROOT / "init/init.tee.core.rc"
        self.assertTrue(core.is_file(), "core init action is missing")
        observed = {}
        for trigger, args in commands(core):
            self.assertEqual(trigger, "on post-fs-data")
            self.assertIn(args[0], {"mkdir", "restorecon"})
            self.assertIn(args[1], LEGACY)
            observed.setdefault(args[1], []).append(args[0])
            if args[0] == "mkdir":
                self.assertEqual(int(args[2], 8), 0o700)
                self.assertEqual(args[3:5], ["system", "system"])
        self.assertEqual(observed, {path: ["mkdir", "restorecon"] for path in LEGACY})
        for rc in (ROOT / "init").glob("*.rc"):
            if rc == core:
                continue
            for _, args in commands(rc):
                if args[0] in {"mkdir", "restorecon"} and len(args) > 1:
                    self.assertNotIn(args[1], LEGACY, str(rc))

    def test_vendor_data_setup_stays_in_vendor_init(self):
        bp = (ROOT / "init/Android.bp").read_text()
        module = next(m for m in re.findall(r"prebuilt_etc\s*\{([^}]+)\}", bp, re.DOTALL)
                      if 'name: "init.tee.rc"' in m)
        self.assertIn("vendor: true", module)
        found = {args[1] for _, args in commands(ROOT / "init/init.tee.rc")
                 if args[0] == "mkdir" and args[1].startswith("/data/vendor/")}
        self.assertIn("/data/vendor/sec_storage_data", found)
        self.assertIn("/data/vendor/sec_storage_data_users", found)


if __name__ == "__main__":
    unittest.main()
