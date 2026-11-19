"""Verify exact stock security service paths for teecd /proc/<pid>/cmdline auth."""
import json
import os
from pathlib import Path
import re
import unittest

from extract_utils.file import File, FileArgs
from extract_utils.makefiles import file_stem_package_name
from extract_utils.tools import android_root

ROOT = Path(__file__).resolve().parents[1]


class ServiceNamesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata = json.loads((ROOT / "docs/service-names-20261114.json").read_text())

    def test_stock_unsuffixed_entries_and_no_hisi_rc_fixup(self):
        self.assertFalse((ROOT / "fixups/hisi_services.py").exists())
        files = [
            File(line)
            for line in (ROOT / "proprietary-files.txt").read_text().splitlines()
            if line and not line.startswith("#")
        ]
        for stem, rec in self.metadata["services"].items():
            exec_rel = rec["exec_path"].lstrip("/")
            rc_rel = rec["rc_path"]
            binary = next(f for f in files if f.src == exec_rel)
            pkg_stem, module = file_stem_package_name(binary, can_have_stem=False, any_extension=True)
            self.assertEqual(binary.dst, exec_rel)
            self.assertEqual(module, stem)
            self.assertIsNone(pkg_stem)
            self.assertNotIn(FileArgs.MODULE, binary.args)
            self.assertNotIn(FileArgs.DISABLE_CHECKELF, binary.args)
            self.assertNotIn(FileArgs.DISABLE_DEPS, binary.args)
            self.assertEqual(binary.hash, rec["elf_sha1"])
            rc = next(f for f in files if f.src == rc_rel)
            self.assertEqual(rc.dst, rc_rel)
            self.assertEqual(rc.hash, rec["rc_sha1"])
            self.assertIsNone(rc.fixup_hash)

    def test_stock_exec_paths_match_aosp_selinux_file_contexts(self):
        platform = Path(android_root)
        contexts = [
            ROOT / "sepolicy/vendor/file_contexts",
            platform / "hardware/huawei/sepolicy/hisi/vendor/file_contexts",
            platform / "system/sepolicy/vendor/file_contexts",
        ]
        entries = [
            line.split()
            for p in contexts
            for line in p.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        for rec in self.metadata["services"].values():
            matches = {
                parts[1]
                for parts in entries
                if re.fullmatch(parts[0], rec["exec_path"])
            }
            self.assertEqual(matches, {rec["exec_context"]}, rec["exec_path"])

    def test_init_debug_core_rc_and_vendor_file_contexts_cleanup(self):
        import subprocess
        fc_text = (ROOT / "sepolicy/vendor/file_contexts").read_text()
        self.assertNotIn(".hisi", fc_text)
        debug_rc = (ROOT / "init/init.debug.core.rc").read_text()
        self.assertIn("apexd.status=ready && property:ro.debuggable=1", debug_rc)
        self.assertNotIn("apexd.status=activated", debug_rc)
        self.assertIn("setprop sys.usb.config adb", debug_rc)
        self.assertIn("on post-fs && property:ro.debuggable=1", debug_rc)
        self.assertIn("service blanc_boot_diag /system_ext/bin/blanc-boot-diag.sh", debug_rc)
        usb_rc = (ROOT / "init/init.hisi.usb.rc").read_text()
        self.assertNotIn("ncm.gs7/host_addr ${ro.serialno}", usb_rc)
        common_mk = (ROOT / "common.mk").read_text()
        pkg_blocks = re.findall(r"(?m)^PRODUCT_PACKAGES\s*\+=\s*(?:[^\n]*\\\n)*[^\n]*", common_mk)
        for blk in pkg_blocks:
            self.assertNotIn("init.debug.core.rc", blk)
            self.assertNotIn("blanc-boot-diag.sh", blk)
        dbg_match = re.search(r"(?m)^PRODUCT_PACKAGES_DEBUG\s*\+=\s*(?:[^\n]*\\\n)*[^\n]*", common_mk)
        self.assertIsNotNone(dbg_match)
        self.assertIn("init.debug.core.rc", dbg_match.group())
        self.assertIn("blanc-boot-diag.sh", dbg_match.group())
        sys_prop = (ROOT / "system.prop").read_text().splitlines()
        self.assertIn("ro.bpf.kver_override=5.10.199", sys_prop)
        sh_path = ROOT / "init/blanc-boot-diag.sh"
        self.assertTrue(sh_path.is_file())
        subprocess.run(["sh", "-n", str(sh_path)], check=True)

    def test_extracted_vendor_tree_matches_stock_and_uses_prefer_true(self):
        source = os.environ.get("BLA_ORIGINAL_FILESYSTEMS")
        output = os.environ.get("BLA_EXTRACTED_VENDOR")
        if not source or not output:
            self.skipTest("set BLA_ORIGINAL_FILESYSTEMS and BLA_EXTRACTED_VENDOR")
        root = Path(output)
        bp = (root / "Android.bp").read_text()
        makefile = (root / "kirin970-common-vendor.mk").read_text()
        for module, rec in self.metadata["services"].items():
            exec_rel = rec["exec_path"].lstrip("/")
            rc_rel = rec["rc_path"]
            block = re.search(
                r'(?ms)^cc_prebuilt_binary \{\n(?:(?!^\}).)*?name: "'
                + re.escape(module)
                + r'",(?:(?!^\}).)*?^\}',
                bp,
            )
            self.assertIsNotNone(block, module)
            block_txt = block.group()
            self.assertNotIn('stem:', block_txt)
            self.assertIn('prefer: true', block_txt)
            self.assertIn('soc_specific: true', block_txt)
            self.assertIn('relative_install_path: "hw"', block_txt)
            self.assertIn(f'proprietary/{exec_rel}', block_txt)
            self.assertIn(
                f'proprietary/{rc_rel}:$(TARGET_COPY_OUT_VENDOR)/'
                + rc_rel.removeprefix("vendor/"),
                makefile,
            )
            self.assertEqual((Path(source) / exec_rel).read_bytes(), (root / "proprietary" / exec_rel).read_bytes())
            self.assertEqual((Path(source) / rc_rel).read_bytes(), (root / "proprietary" / rc_rel).read_bytes())
            self.assertFalse((root / "proprietary" / (exec_rel + ".hisi")).exists())
            self.assertFalse((root / "proprietary" / rc_rel.replace(".rc", ".hisi.rc")).exists())


if __name__ == "__main__":
    unittest.main()
