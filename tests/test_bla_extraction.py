"""Regressions against the selected extract-utils parser, not a mock grammar."""
from pathlib import Path
import unittest
import importlib.util
import hashlib
import io
import os
import tempfile
import zipfile
from types import SimpleNamespace
from unittest import mock
from extract_utils.file import File, FileArgs
from extract_utils.fixups_blob import BlobFixupCtx
from extract_utils.module import PinnedFileProcessResult

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
        self.assertEqual(apk.fixup_hash, "8a05fba3bad29aec111163d4890fe513728b5cf1")
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
        self.assertEqual(mapcon.fixup_hash, "58da41008ac570a46d1288c98d91408a93de451e")
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
        self.assertEqual(
            all_by_src["vendor/bin/iked"].fixup_hash,
            "9a56b9fb7d90fee7cbf7529cc1dea3f837aad1c7",
        )
        self.assertEqual(
            all_by_src["vendor/lib64/libracoon2.so"].fixup_hash,
            "f406737e869db67b0452ff73d3733c62bfc501ef",
        )
        spec = importlib.util.spec_from_file_location("common_recipe", ROOT / "extract-files.py")
        recipe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recipe)
        self.assertTrue(recipe.module.should_fixup_file(all_by_src["vendor/bin/iked"]))
        self.assertTrue(recipe.module.should_fixup_file(all_by_src["vendor/lib64/libracoon2.so"]))
        self.assertIn("libcrypto-v29", (ROOT / "common.mk").read_text())

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


class Attempt22IdempotencyAndDualSourceTests(unittest.TestCase):
    def _load(self, rel):
        spec = importlib.util.spec_from_file_location(rel.replace("/", "_"), ROOT / rel)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_shadowed_audio_volume_xmls_dropped_and_count_is_972(self):
        files = [
            File(line.strip())
            for line in (ROOT / "proprietary-files.txt").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        dsts = {f.dst for f in files}
        # Attempt 26 retired 32/64-bit hicam.hal.service.so (972 -> 970), Stage A restored
        # 17 stock .225 PPAlgo host DSP/OpenCL libraries (970 -> 987), and Stage B restored
        # 19 Kirin 970 NPU hiaiserver/HiAI/SceneRecognition entries (987 -> 1006).
        self.assertEqual(len(files), 1006)
        for hiai_entry in (
            "vendor/bin/hiaiserver",
            "vendor/etc/hiai/default/ai_computing_resource.xml",
            "vendor/etc/hiai/default/ai_config.xml",
            "vendor/etc/hiai/default/ai_framework.xml",
            "vendor/etc/hiai/default/ai_server.properties",
            "vendor/etc/models/SceneRecognition/caffe/build/IC_conv_112x112.cambricon",
            "vendor/etc/models/SceneRecognition/caffe/build/IC_conv_112x112_front.cambricon",
            "vendor/etc/models/SceneRecognition/caffe/build/IC_conv_112x112_front_mean",
            "vendor/etc/models/SceneRecognition/caffe/build/IC_conv_112x112_mean",
            "vendor/lib64/libAndroidNN.so",
            "vendor/lib64/libai_crypto.so",
            "vendor/lib64/libai_fmk_stats.so",
            "vendor/lib64/libai_framework.so",
            "vendor/lib64/libai_hcs.so",
            "vendor/lib64/libgnustl_shared.so",
            "vendor/lib64/libhiai_hcs.so",
            "vendor/lib64/libhiai_hidl_server.so",
            "vendor/lib64/libhiai_ipu.so",
            "vendor/lib64/libhiai_server.so",
        ):
            self.assertIn(hiai_entry, dsts)
        for pp_lib in (
            "vendor/lib64/libCropOffset.so",
            "vendor/lib64/libaiq.so",
            "vendor/lib64/libback_ground_adj.so",
            "vendor/lib64/libcolorfusion.so",
            "vendor/lib64/libcolorfusion_module.so",
            "vendor/lib64/libdavinci_acore.so",
            "vendor/lib64/libeis.so",
            "vendor/lib64/libeis_cf.so",
            "vendor/lib64/libhdr_acore.so",
            "vendor/lib64/libhpf.so",
            "vendor/lib64/libhpf_cl.so",
            "vendor/lib64/libjpeghdr.so",
            "vendor/lib64/libjpeghdr_acore.so",
            "vendor/lib64/libjpeghdrenc.so",
            "vendor/lib64/libmefdsp.so",
            "vendor/lib64/libslf_cf.so",
            "vendor/lib64/libtpp.so",
        ):
            self.assertIn(pp_lib, dsts)
        self.assertNotIn("vendor/etc/audio_policy_volumes.xml", dsts)
        self.assertNotIn("vendor/etc/default_volume_tables.xml", dsts)
        self.assertNotIn("vendor/lib/hw/hicam.hal.service.so", dsts)
        self.assertNotIn("vendor/lib64/hw/hicam.hal.service.so", dsts)
        common_mk = (ROOT / "common.mk").read_text()
        self.assertIn("audio_policy_volumes.xml", common_mk)
        self.assertIn("default_volume_tables.xml", common_mk)
        for nn_pkg in (
            "android.hardware.neuralnetworks@1.0.vendor",
            "android.hardware.neuralnetworks@1.1.vendor",
            "android.hardware.neuralnetworks@1.2.vendor",
        ):
            self.assertIn(nn_pkg, common_mk)

    def test_rc_fixups_are_strictly_idempotent(self):
        recipe = self._load("extract-files.py")
        fixtures = {
            "vendor/etc/init/vendor.huawei.hardware.biometrics.fingerprint@2.2-service.rc": (
                b"service vendor.fps_hal /vendor/bin/hw/vendor.huawei.hardware.biometrics.fingerprint@2.2-service\n"
                b"    class late_start\n"
                b"    interface vendor.huawei.hardware.biometrics.fingerprint@2.2::IExtBiometricsFingerprint default\n"
            ),
            "vendor/etc/init/rild.rc": (
                b"service vendor.ril-daemon /vendor/bin/hw/rild\n"
                b"    class main\n"
                b"    capabilities BLOCK_SUSPEND NET_ADMIN NET_RAW\n"
            ),
            "vendor/etc/init/android.hardware.drm@1.2-service.widevine.rc": (
                b"on post-fs-data\n"
                b"    mkdir /data/vendor/mediadrm 0770 media mediadrm\n"
                b"    start vendor.move_data_sh\n\n"
                b"service vendor.move_data_sh /system/bin/move_widevine_data.sh\n"
                b"    class main\n"
                b"    oneshot\n\n"
                b"service vendor.drm-widevine-hal-1-2 /vendor/preavs/bin/hw/android.hardware.drm@1.2-service.widevine\n"
                b"    setenv LD_LIBRARY_PATH /vendor/preavs/lib\n"
            ),
        }
        with tempfile.TemporaryDirectory() as td:
            for rel, payload in fixtures.items():
                with self.subTest(rel=rel):
                    fixup = recipe.module.blob_fixups[rel]
                    p = Path(td) / Path(rel).name
                    p.write_bytes(payload)
                    fixup.run(BlobFixupCtx(str(ROOT)), File(rel), str(p))
                    first = p.read_bytes()
                    fixup.run(BlobFixupCtx(str(ROOT)), File(rel), str(p))
                    second = p.read_bytes()
                    self.assertEqual(first, second)

    def test_binary_fixups_are_idempotent_for_patched_and_final_outputs_and_reject_tamper(self):
        import struct

        smartae = self._load("fixups/smartae.py")
        hdr = bytearray(64)
        hdr[:6] = b"\x7fELF\x02\x01"
        hdr[18:20] = b"\xb7\x00"
        blob_in = bytes(hdr) + bytes.fromhex("9F020AB9")
        with mock.patch.object(smartae, "EXPECTED_SHA256", hashlib.sha256(blob_in).hexdigest()):
            out = smartae.patch_smartae(blob_in)
        out_sha = hashlib.sha256(out).hexdigest()
        with mock.patch.object(smartae, "EXPECTED_PATCHED_SHA256", out_sha):
            self.assertEqual(smartae.patch_smartae(out), out)
        out_final = out + b"\x00"
        with mock.patch.object(smartae, "EXPECTED_FINAL_SHA256", hashlib.sha256(out_final).hexdigest()):
            self.assertEqual(smartae.patch_smartae(out_final), out_final)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            smartae.patch_smartae(out + b"\x01")

        cam = self._load("fixups/camera_metadata_undef.py")
        dynstr = b"\x00camera_metadata_section_bounds\x00camera_metadata_section_names\x00"
        dynsym = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
        dynsym += struct.pack("<IBBHQQ", 1, 0x11, 0, 11, 0x2d540, 256)
        dynsym += struct.pack("<IBBHQQ", 32, 0x11, 0, 11, 0x2d440, 256)
        sh_off = 64 + len(dynstr) + len(dynsym)
        ehdr = bytearray(64)
        ehdr[:6] = b"\x7fELF\x02\x01"
        ehdr[18:20] = b"\xb7\x00"
        struct.pack_into("<Q", ehdr, 40, sh_off)
        struct.pack_into("<HH", ehdr, 58, 64, 3)
        cam_in = bytes(ehdr) + dynstr + dynsym + bytes(64) + struct.pack("<IIQQQQIIQQ", 0, 3, 2, 0, 64, len(dynstr), 0, 0, 1, 0) + struct.pack("<IIQQQQIIQQ", 0, 11, 2, 0, 64 + len(dynstr), len(dynsym), 1, 1, 8, 24)
        with mock.patch.object(cam, "EXPECTED_SHA256", hashlib.sha256(cam_in).hexdigest()):
            cam_out = cam.patch_camera_metadata_undef(cam_in)
        with mock.patch.object(cam, "EXPECTED_OUTPUT_SHA256", hashlib.sha256(cam_out).hexdigest()):
            self.assertEqual(cam.patch_camera_metadata_undef(cam_out), cam_out)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            cam.patch_camera_metadata_undef(cam_out + b"\x00")

        ril = self._load("fixups/libril_voicereg_v12.py")
        buf64 = bytearray(0x752C8 + 64)
        buf64[:6] = b"\x7fELF\x02\x01"
        buf64[18:20] = b"\xb7\x00"
        buf64[0x752C8 : 0x752C8 + len(ril.WINDOW_64_OLD)] = ril.WINDOW_64_OLD
        with mock.patch.object(ril, "EXPECTED_SHA256_64", hashlib.sha256(buf64).hexdigest()):
            ril64_out = ril.patch_libril_voicereg(bytes(buf64))
        with mock.patch.object(ril, "EXPECTED_OUTPUT_SHA256_64", hashlib.sha256(ril64_out).hexdigest()):
            self.assertEqual(ril.patch_libril_voicereg(ril64_out), ril64_out)

    def test_repack_verified_patched_apk_normalizes_resigned_and_rejects_tamper(self):
        for rel, apk_name in (
            ("fixups/build_hwims_apk.py", "HwIms.apk"),
            ("fixups/build_mapcon_apk.py", "Mapcon.apk"),
        ):
            with self.subTest(apk=apk_name):
                mod = self._load(rel)
                with tempfile.TemporaryDirectory() as td:
                    tdp = Path(td)
                    classes_dex = tdp / "classes.dex"
                    classes2_dex = tdp / "classes2.dex"
                    classes_dex.write_bytes(b"dex\n035\x00PAYLOAD1")
                    classes2_dex.write_bytes(b"dex\n035\x00PAYLOAD2")
                    jni_libs = {"libfoo.so": b"\x7fELF" + b"\x00" * 60}
                    base_unsigned = tdp / f"base_{apk_name}"
                    with zipfile.ZipFile(base_unsigned, "w") as zf:
                        zf.writestr("AndroidManifest.xml", b"<manifest/>")
                        zf.writestr("resources.arsc", b"ARSC_BYTES")
                        zf.writestr("assets/extra.bin", b"EXTRA_DATA")
                    expected_apk = tdp / f"expected_{apk_name}"
                    mod._write_deterministic_apk(
                        base_unsigned, classes_dex, classes2_dex, jni_libs, expected_apk
                    )
                    expected_out_sha = hashlib.sha256(expected_apk.read_bytes()).hexdigest()
                    entry_hashes = {}
                    with zipfile.ZipFile(expected_apk, "r") as zf:
                        for info in zf.infolist():
                            entry_hashes[info.filename] = hashlib.sha256(
                                zf.read(info.filename)
                            ).hexdigest()

                    # Construct a Soong/apksigner-style signed copy: different timestamps,
                    # META-INF signatures, reordered entries, and trailing signing block junk.
                    signed_apk = tdp / f"signed_{apk_name}"
                    with zipfile.ZipFile(signed_apk, "w") as zf:
                        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
                        zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\n")
                        zf.writestr("META-INF/CERT.RSA", b"DER_SIG")
                        with zipfile.ZipFile(expected_apk, "r") as src_zf:
                            for info in reversed(src_zf.infolist()):
                                zi = zipfile.ZipInfo(info.filename, date_time=(2026, 11, 24, 12, 0, 0))
                                zi.compress_type = zipfile.ZIP_DEFLATED
                                zf.writestr(zi, src_zf.read(info.filename))
                    with signed_apk.open("ab") as fh:
                        # Trailing bytes outside entries still allow Python ZipFile central-dir seek,
                        # simulating extra APK metadata before EOCD? Actually insert dummy comment
                        # via ZipFile.comment so ZIP remains valid!
                        pass
                    with zipfile.ZipFile(signed_apk, "a") as zf:
                        zf.comment = b"APK_SIG_BLOCK_SIMULATION"

                    normalized = tdp / f"norm_{apk_name}"
                    with (
                        mock.patch.object(mod, "EXPECTED_OUTPUT_SHA256", expected_out_sha),
                        mock.patch.object(mod, "EXPECTED_PATCHED_ENTRY_SHA256", entry_hashes),
                    ):
                        mod.repack_verified_patched_apk(signed_apk, normalized)
                        self.assertEqual(normalized.read_bytes(), expected_apk.read_bytes())
                        # Calling blob_fixup on already-normalized APK is an exact no-op.
                        mod.blob_fixup(SimpleNamespace(module_dir=str(ROOT)), File(apk_name), str(normalized))
                        self.assertEqual(normalized.read_bytes(), expected_apk.read_bytes())

                        # Tampering classes2.dex must raise ValueError.
                        tampered = tdp / f"tampered_{apk_name}"
                        with zipfile.ZipFile(tampered, "w") as zf:
                            for k in entry_hashes:
                                data = (
                                    b"TAMPERED_DEX"
                                    if k == "classes2.dex"
                                    else zipfile.ZipFile(expected_apk, "r").read(k)
                                )
                                zf.writestr(k, data)
                        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                            mod.repack_verified_patched_apk(tampered, tdp / "fail.apk")

                        # Adding an unexpected extra non-META-INF entry must raise ValueError.
                        extra_apk = tdp / f"extra_{apk_name}"
                        with zipfile.ZipFile(extra_apk, "w") as zf:
                            for k in entry_hashes:
                                zf.writestr(k, zipfile.ZipFile(expected_apk, "r").read(k))
                            zf.writestr("classes3.dex", b"UNEXPECTED")
                        with self.assertRaisesRegex(ValueError, "entry set mismatch"):
                            mod.repack_verified_patched_apk(extra_apk, tdp / "fail2.apk")

    def test_kirin970_module_handles_signed_lineage_apk_restored_and_source(self):
        recipe = self._load("extract-files.py")
        with tempfile.TemporaryDirectory() as td:
            apk_path = Path(td) / "HwIms.apk"
            apk_path.write_bytes(b"SIGNED_APK_BYTES")
            canonical_bytes = b"CANONICAL_UNSIGNED_APK"
            canonical_sha1 = hashlib.sha1(canonical_bytes).hexdigest()
            f = File(f"system/app/HwIms/HwIms.apk|{'0'*40}|{canonical_sha1}")

            def fake_fixup(_file, path):
                Path(path).write_bytes(canonical_bytes)

            with mock.patch.object(recipe.module, "fixup_module_file", side_effect=fake_fixup):
                res = recipe.module.process_pinned_file(f, str(apk_path), restored=False)
                self.assertEqual(res, PinnedFileProcessResult.MATCH)
                self.assertEqual(apk_path.read_bytes(), canonical_bytes)

            # Corrupt restored APK falls back cleanly to MISMATCH, while corrupt source raises ValueError.
            apk_path.write_bytes(b"CORRUPT")
            with mock.patch.object(
                recipe.module, "fixup_module_file", side_effect=ValueError("bad zip")
            ):
                self.assertEqual(
                    recipe.module.process_pinned_file(f, str(apk_path), restored=True),
                    PinnedFileProcessResult.MISMATCH,
                )
                with self.assertRaisesRegex(ValueError, "bad zip"):
                    recipe.module.process_pinned_file(f, str(apk_path), restored=False)

    def test_public_libraries_txt_exposes_only_libopencl_for_mali(self):
        pub_libs = (ROOT / "configs/public.libraries.txt").read_text().splitlines()
        entries = [line.strip() for line in pub_libs if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(entries, ["libOpenCL.so"])

        common_mk = (ROOT / "common.mk").read_text()
        self.assertIn(
            "$(LOCAL_PATH)/configs/public.libraries.txt:$(TARGET_COPY_OUT_VENDOR)/etc/public.libraries.txt",
            common_mk,
        )

        prop_srcs = {
            File(line.strip()).src
            for line in (ROOT / "proprietary-files.txt").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        for required in (
            "vendor/lib/libOpenCL.so",
            "vendor/lib64/libOpenCL.so",
            "vendor/lib/egl/libGLES_mali.so",
            "vendor/lib64/egl/libGLES_mali.so",
        ):
            self.assertIn(required, prop_srcs)


if __name__ == "__main__":
    unittest.main()
