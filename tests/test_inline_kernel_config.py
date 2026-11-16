# SPDX-FileCopyrightText: The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
"""Evaluate inline kernel Make variables across BoardConfigCommon.mk, BoardConfigKernel.mk, and kernel.mk."""
import os
from pathlib import Path
import shlex
import subprocess
import unittest

COMMON = Path(__file__).resolve().parents[1]


class InlineKernelConfigTest(unittest.TestCase):
    def test_inline_kernel_flags_match_standalone_kbuild_contract(self):
        top = os.environ.get("ANDROID_BUILD_TOP")
        if not top:
            self.skipTest("Set ANDROID_BUILD_TOP to evaluate LineageOS kernel Make includes")
        top_path = Path(top).resolve()
        make_bin = top_path / "prebuilts/build-tools/linux-x86/bin/make"
        self.assertTrue(make_bin.is_file(), f"Missing prebuilt make: {make_bin}")

        makefile = "\n".join([
            "HOST_PREBUILT_TAG := linux-x86",
            "TARGET_BUILD_VARIANT := userdebug",
            "TARGET_PRODUCT := lineage_blanc",
            "PRODUCT_TARGET_VNDK_VERSION := 29",
            "OUT_DIR := out/lineage-24.0",
            f"TARGET_OUT_INTERMEDIATES := {top_path}/out/lineage-24.0/target/product/blanc/obj",
            "BOARD_SUPER_PARTITION_SIZE := 5771362304",
            "DEVICE_PATH := device/huawei/blanc",
            f"include {COMMON / 'BoardConfigCommon.mk'}",
            "KERNEL_ARCH := $(TARGET_ARCH)",
            f"include {top_path / 'vendor/lineage/config/BoardConfigKernel.mk'}",
            "TARGET_NO_KERNEL :=",
            "TARGET_NO_KERNEL_OVERRIDE :=",
            "TARGET_KERNEL_PLATFORM_TARGET :=",
            "TARGET_PREBUILT_KERNEL :=",
            "TARGET_FORCE_PREBUILT_KERNEL :=",
            "BUILDING_VENDOR_IMAGE := true",
            "TARGET_ROOT_OUT := out/target/product/blanc/root",
            "TARGET_OUT := out/target/product/blanc/system",
            "TARGET_OUT_VENDOR := out/target/product/blanc/vendor",
            "TARGET_OUT_PRODUCT := out/target/product/blanc/product",
            "TARGET_RAMDISK_OUT := out/target/product/blanc/ramdisk",
            f"include {top_path / 'vendor/lineage/build/tasks/kernel.mk'}",
            "$(info KERNEL_CC=$(KERNEL_CC))",
            "$(info KERNEL_CROSS_COMPILE=$(KERNEL_CROSS_COMPILE))",
            "$(info KERNEL_MAKE_FLAGS=$(KERNEL_MAKE_FLAGS))",
            "$(info FULL_KERNEL_BUILD=$(FULL_KERNEL_BUILD))",
            "all:",
            "\t@:",
        ])
        proc = subprocess.run(
            [str(make_bin), "-rR", "-s", "-f", "-"],
            input=makefile,
            cwd=top_path,
            text=True,
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        vals = {}
        for line in proc.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k in ("KERNEL_CC", "KERNEL_CROSS_COMPILE", "KERNEL_MAKE_FLAGS", "FULL_KERNEL_BUILD"):
                    vals[k] = v

        self.assertEqual(vals["FULL_KERNEL_BUILD"], "true")

        # 1. KERNEL_CC uses clang-r416183b explicitly and does NOT inject LD=ld.lld
        expected_clang = str(top_path / "prebuilts/clang/kernel/linux-x86/clang-r416183b/bin/clang")
        self.assertEqual(vals["KERNEL_CC"], f'CC="{expected_clang}"')
        self.assertNotIn("LD=ld.lld", vals["KERNEL_CC"])
        self.assertTrue(Path(expected_clang).is_file())

        # 2. KERNEL_CROSS_COMPILE sets all 3 GNU 4.9 prefixes to real tool binaries
        cc_tokens = dict(tok.split("=", 1) for tok in shlex.split(vals["KERNEL_CROSS_COMPILE"]))
        for var, expected_bin in (
            ("CROSS_COMPILE", "aarch64/aarch64-linux-android-4.9/bin/aarch64-linux-android-ld"),
            ("CROSS_COMPILE_ARM32", "arm/arm-linux-androideabi-4.9/bin/arm-linux-androidkernel-ld"),
            ("CROSS_COMPILE_COMPAT", "arm/arm-linux-androideabi-4.9/bin/arm-linux-androidkernel-ld"),
        ):
            self.assertIn(var, cc_tokens)
            tool = Path(cc_tokens[var] + "ld")
            self.assertEqual(tool, top_path / "prebuilts/gcc/linux-x86" / expected_bin)
            self.assertTrue(tool.is_file(), f"Missing GNU binutils tool: {tool}")

        # 3. Trailing overrides in KERNEL_MAKE_FLAGS supersede BoardConfigKernel.mk defaults
        flags = shlex.split(vals["KERNEL_MAKE_FLAGS"])
        j_flags = [f for f in flags if f.startswith("-j")]
        self.assertEqual(j_flags[-1], "-j8")
        kv = {}
        for tok in flags:
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv[k] = v
        self.assertEqual(kv["LLVM"], "")
        self.assertEqual(kv["LLVM_IAS"], "0")
        self.assertEqual(kv["HOSTCC"], expected_clang)
        self.assertEqual(kv["HOSTCXX"], expected_clang + "++")
        self.assertEqual(kv["HOSTCFLAGS"], "-fuse-ld=lld -Wno-unused-command-line-argument")
        self.assertEqual(kv["HOSTLDFLAGS"], "-L/usr/lib/x86_64-linux-gnu -L/usr/lib64 -fuse-ld=lld")
        self.assertEqual(kv["TARGET_BOARD_PLATFORM"], "kirin970")


if __name__ == "__main__":
    unittest.main()
