# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
"""Verify /metadata -> by-name/cache, /cache -> /data/cache, BoardConfig, and SELinux block labels."""
import os
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


def parse_fstab(path):
    entries = []
    for raw in path.read_text().splitlines():
        line = raw.partition("#")[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 5:
            raise AssertionError(f"Expected 5 fstab fields in {path}: {raw!r}")
        entries.append(
            {
                "src": fields[0],
                "mnt_point": fields[1],
                "type": fields[2],
                "mnt_flags": fields[3],
                "fs_mgr_flags": fields[4].split(","),
            }
        )
    return entries


def load_file_contexts(path):
    rules = []
    for raw in path.read_text().splitlines():
        line = raw.partition("#")[0].strip()
        if not line:
            continue
        pattern, context = line.split()
        rules.append((pattern, context))
    return rules


def lookup_context_type(rules, path):
    matched = [ctx.split(":")[2] for pat, ctx in rules if re.fullmatch(pat, path)]
    if len(matched) != 1:
        raise AssertionError(f"Expected exactly 1 file_contexts match for {path}: {matched}")
    return matched[0]


class MetadataFstabTests(unittest.TestCase):
    def test_fstab_maps_metadata_to_cache_and_drops_cache_and_patch(self):
        entries = parse_fstab(ROOT / "init/fstab.kirin970")
        metadata = [e for e in entries if e["mnt_point"] == "/metadata"]
        self.assertEqual(len(metadata), 1)
        entry = metadata[0]
        self.assertEqual(entry["src"], "/dev/block/by-name/cache")
        self.assertEqual(entry["type"], "ext4")
        self.assertEqual(entry["mnt_flags"], "noatime,nosuid,nodev")
        for flag in ("wait", "check", "formattable", "first_stage_mount"):
            self.assertIn(flag, entry["fs_mgr_flags"])

        for fstab_name in ("init/fstab.kirin970", "init/fstab.modem"):
            all_entries = parse_fstab(ROOT / fstab_name)
            self.assertEqual([e for e in all_entries if e["mnt_point"] == "/cache"], [], fstab_name)
            self.assertEqual([e for e in all_entries if e["src"] == "/dev/block/by-name/patch"], [], fstab_name)

    def test_no_rc_files_reference_by_name_cache_or_patch(self):
        for rc in (ROOT / "init").rglob("*.rc"):
            text = rc.read_text()
            self.assertNotIn("by-name/cache", text, str(rc))
            self.assertNotIn("by-name/patch", text, str(rc))

    def test_board_config_uses_metadata_and_omits_cacheimage(self):
        text = (ROOT / "BoardConfigCommon.mk").read_text()
        self.assertRegex(text, r"(?m)^BOARD_USES_METADATA_PARTITION\s*:=\s*true\b", msg="BOARD_USES_METADATA_PARTITION must be true")
        self.assertNotRegex(text, r"(?m)^\s*BOARD_CACHEIMAGE_FILE_SYSTEM_TYPE\b", msg="BOARD_CACHEIMAGE_FILE_SYSTEM_TYPE must be omitted")
        self.assertNotRegex(text, r"(?m)^\s*BOARD_CACHEIMAGE_PARTITION_SIZE\b", msg="BOARD_CACHEIMAGE_PARTITION_SIZE must be omitted")

        top = os.environ.get("ANDROID_BUILD_TOP")
        if not top:
            return
        top_path = Path(top).resolve()
        make_bin = top_path / "prebuilts/build-tools/linux-x86/bin/make"
        if not make_bin.is_file():
            self.skipTest(f"Missing prebuilt make: {make_bin}")
        fragment = "\n".join(
            [
                "HOST_PREBUILT_TAG := linux-x86",
                "TARGET_BUILD_VARIANT := userdebug",
                "TARGET_PRODUCT := lineage_blanc",
                "BOARD_SUPER_PARTITION_SIZE := 5771362304",
                "DEVICE_PATH := device/huawei/blanc",
                f"include {ROOT / 'BoardConfigCommon.mk'}",
                "$(info uses_metadata=$(BOARD_USES_METADATA_PARTITION))",
                "$(info cache_fs_type=$(BOARD_CACHEIMAGE_FILE_SYSTEM_TYPE))",
                "$(info cache_size=$(BOARD_CACHEIMAGE_PARTITION_SIZE))",
                "all:",
                "\t@:",
            ]
        )
        proc = subprocess.run(
            [str(make_bin), "-rR", "-s", "-f", "-"],
            input=fragment,
            cwd=top_path,
            text=True,
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        vals = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
        self.assertEqual(vals["uses_metadata"], "true")
        self.assertEqual(vals["cache_fs_type"], "")
        self.assertEqual(vals["cache_size"], "")

    def test_selinux_file_contexts_label_kirin970_block_devices(self):
        rules = load_file_contexts(ROOT / "sepolicy/vendor/file_contexts")
        expected_by_name = {
            "cache": "metadata_block_device",
            "userdata": "userdata_block_device",
            "super": "super_block_device",
            "misc": "misc_block_device",
            "recovery_ramdisk": "recovery_block_device",
            "dto": "dtbo_block_device",
            "dtbo": "dtbo_block_device",
            "frp": "frp_block_device",
            "boot": "boot_block_device",
            "kernel": "boot_block_device",
            "ramdisk": "boot_block_device",
            "nvme": "vendor_nve_block_device",
            "oeminfo": "vendor_oeminfo_nvm_device",
            "certification": "vendor_certification_device",
            "secure_storage": "vendor_teecd_blkdev",
            "splash2": "vendor_splash2_block_device",
            "hisee_fs": "vendor_hisee_blkdev",
            "rrecord": "vendor_bfm_block_device",
            "modem_fw": "vendor_modem_block_device",
            "modemnvm_img": "vendor_modem_block_device",
            "isp_firmware": "vendor_fw_block_device",
            "isp_boot": "vendor_fw_block_device",
            "fw_hifi": "vendor_fw_block_device",
            "vrl": "vendor_fw_block_device",
            "vrl_backup": "vendor_fw_block_device",
        }
        for name, expected_type in expected_by_name.items():
            for prefix in ("/dev/block/by-name/", "/dev/block/platform/ff3c0000.ufs/by-name/"):
                path = prefix + name
                with self.subTest(path=path):
                    self.assertEqual(lookup_context_type(rules, path), expected_type)
        self.assertEqual(lookup_context_type(rules, "/dev/block/zram0"), "swap_block_device")
        self.assertEqual(lookup_context_type(rules, "/dev/block/sdd5"), "vendor_certification_device")
        self.assertEqual(lookup_context_type(rules, "/dev/block/sdd"), "vendor_ufs_block_device")
        self.assertEqual(
            lookup_context_type(rules, "/sys/devices/platform/ff3c0000.ufs/host0/target0:0:0/0:0:0:3/block/sdd/sdd70/partition"),
            "sysfs_devices_block",
        )

    def test_writable_ext4_mounts_use_xattr_and_readonly_mounts_use_context(self):
        kirin_entries = {e["mnt_point"]: e for e in parse_fstab(ROOT / "init/fstab.kirin970")}
        for mnt in ("/splash2", "/sec_storage"):
            with self.subTest(mnt=mnt):
                self.assertNotIn("context=", kirin_entries[mnt]["mnt_flags"])
                self.assertNotIn("crypt", kirin_entries[mnt]["fs_mgr_flags"])
                self.assertIn("check", kirin_entries[mnt]["fs_mgr_flags"])
        self.assertIn("context=u:object_r:hisee_data_file:s0", kirin_entries["/mnt/hisee_fs"]["mnt_flags"])

        modem_entries = {e["mnt_point"]: e for e in parse_fstab(ROOT / "init/fstab.modem")}
        for mnt in ("/mnt/modem/modem_secure", "/modem_log", "/mnt/modem/mnvm2:0"):
            with self.subTest(mnt=mnt):
                self.assertNotIn("context=", modem_entries[mnt]["mnt_flags"])
        self.assertIn("context=u:object_r:modem_vendor_file:s0", modem_entries["/vendor/modem/modem_fw"]["mnt_flags"])

    def test_system_properties_separated_from_vendor_prop(self):
        moved = {
            "persist.rog_feature",
            "persist.kirin.media.offload.enable",
            "persist.kirin.media.hires.enable",
            "persist.kirin.media.lowlatency.enable",
            "persist.kirin.media.usbvoice.enable",
            "persist.kirin.media.usbvoice.name",
            "ro.netflix.bsp_rev",
            "ro.kirin.product.platform",
            "ro.comp.chipset_version",
            "persist.radio.dualltecap",
            "use_sensorhub_labc",
            "persist.kirin.touch_vsync_opt",
            "ro.config.hw_volte_on",
        }
        sys_keys = {
            line.split("=", 1)[0].strip()
            for line in (ROOT / "system.prop").read_text().splitlines()
            if "=" in line and not line.lstrip().startswith("#")
        }
        vnd_keys = {
            line.split("=", 1)[0].strip()
            for line in (ROOT / "vendor.prop").read_text().splitlines()
            if "=" in line and not line.lstrip().startswith("#")
        }
        expected_sys_keys = moved | {
            "ro.bpf.kver_override",
            "persist.radio.defdualltecap",
            "ro.config.hw_volte_dyn",
            "ro.config.hw_ut_ims",
            "ro.config.hw_vowifi",
            "ro.config.hw_vowifi_mmsut",
            "persist.dbg.volte_avail_ovr",
            "persist.dbg.wfc_avail_ovr",
        }
        self.assertEqual(sys_keys, expected_sys_keys)
        self.assertEqual(vnd_keys & expected_sys_keys, set())
        self.assertIn("ro.vendor.config.hw_vowifi", vnd_keys)
        self.assertRegex((ROOT / "BoardConfigCommon.mk").read_text(), r"(?m)^TARGET_SYSTEM_PROP\s*\+=\s*\$\(COMMON_PATH\)/system\.prop\b")

    def test_attempt13_vowifi_init_and_proprietary_staging(self):
        plat_rc = (ROOT / "init/init.platform.rc").read_text()
        self.assertIn("mkdir /data/vendor/iked_config 0770 root system", plat_rc)
        self.assertIn("mkdir /data/vendor/hinetmanager 0770 root system", plat_rc)
        self.assertIn("service iked /vendor/bin/iked", plat_rc)
        self.assertIn("interface vendor.huawei.hardware.iked@1.0::IIkedDevice default", plat_rc)

        vowifi_rc = (ROOT / "init/init.vowifi.rc").read_text()
        self.assertNotIn("on early-boot", vowifi_rc)
        self.assertIn("service hivwserver /vendor/bin/hivwserver", vowifi_rc)

        hinet_rc = (ROOT / "init/hinetmanager.rc").read_text()
        self.assertIn("service hinetmanager /vendor/bin/hinetmanager", hinet_rc)
        self.assertIn("interface vendor.huawei.hardware.hinetmanager@1.0::IHinetmanagerDevice default", hinet_rc)
        self.assertNotIn("dsm", hinet_rc)

        props_txt = (ROOT / "proprietary-files.txt").read_text()
        for entry in (
            "system/app/Mapcon/Mapcon.apk|",
            "vendor/bin/iked|",
            "vendor/bin/hinetmanager|",
            "vendor/bin/hivwserver|",
            "vendor/lib64/libracoon2.so|",
            "vendor/lib64/vendor.huawei.hardware.iked@1.0.so|",
            "vendor/lib64/vendor.huawei.hardware.hinetmanager@1.0.so|",
        ):
            self.assertIn(entry, props_txt)


if __name__ == "__main__":
    unittest.main()
