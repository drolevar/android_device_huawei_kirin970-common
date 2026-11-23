# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
"""Deterministically deodex, patch, shim, and repack .225 Mapcon.apk for Android 17 VoWiFi."""

from __future__ import annotations

import hashlib
import inspect
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

FIXED_ZIP_DT = (2009, 1, 1, 0, 0, 0)
PAGE_ALIGN_BYTES = 16384

EXPECTED_INPUT_SHA256 = {
    "app/Mapcon/Mapcon.apk": "11a150cb50374235984a70f291a8b9445da22316dca4018b4543398b17eceeef",
    "app/Mapcon/oat/arm64/Mapcon.odex": "4f3b48f702da124aa11727d4d9af4c054fa5e98c8c462be0bd3186d67105c488",
    "app/Mapcon/oat/arm64/Mapcon.vdex": "921239b98aab6e5dc9f2b81bfaeeb6ac404ab94a0e34cba31efa7d24f5059431",
    "lib64/libvowifiqoe.so": "f570667ad5d91da5626ee64969567bec4ad93a50f7615a88be1263a057ed834c",
    "lib64/libc_secshared.so": "b534bb3e8ca226d169875b7027daec8606d9dd86d1a356498adb8fe7abfbd778",
}

APEX_BOOT_ARCHIVES = (
    "com.android.runtime.release.apex",
    "com.android.conscrypt.apex",
    "com.android.media.apex",
)

CLEAN_DEODEX_JAVA = """\
import com.android.tools.smali.baksmali.Baksmali;
import com.android.tools.smali.baksmali.BaksmaliOptions;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.analysis.ClassPath;
import com.android.tools.smali.dexlib2.analysis.ClassProvider;
import com.android.tools.smali.dexlib2.analysis.DexClassProvider;
import com.android.tools.smali.dexlib2.dexbacked.OatFile;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.MultiDexContainer;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CleanDeodex {
    private static void addContainer(File f, Opcodes opcodes, List<ClassProvider> out) {
        try {
            MultiDexContainer<? extends DexFile> c = DexFileFactory.loadDexContainer(f, opcodes);
            for (String entry : c.getDexEntryNames()) {
                out.add(new DexClassProvider(c.getEntry(entry).getDexFile()));
            }
        } catch (Exception ignored) {
        }
    }

    public static void main(String[] args) throws Exception {
        File targetOdex = new File(args[0]);
        File outSmaliDir = new File(args[1]);
        Opcodes opcodes = Opcodes.forApi(29);
        List<ClassProvider> providers = new ArrayList<>();
        for (int i = 2; i < args.length; i++) {
            File d = new File(args[i]);
            File[] files = d.listFiles();
            if (files == null) continue;
            Arrays.sort(files);
            for (File f : files) {
                String n = f.getName();
                if (n.endsWith(".jar") || n.endsWith(".oat") || n.endsWith(".odex")) {
                    addContainer(f, opcodes, providers);
                }
            }
        }
        MultiDexContainer<? extends DexFile> targetContainer =
                DexFileFactory.loadDexContainer(targetOdex, opcodes);
        int oatVer = ClassPath.NOT_SPECIFIED;
        if (targetContainer instanceof OatFile) {
            oatVer = ((OatFile) targetContainer).getOatVersion();
        }
        for (String entry : targetContainer.getDexEntryNames()) {
            providers.add(new DexClassProvider(targetContainer.getEntry(entry).getDexFile()));
        }
        BaksmaliOptions opts = new BaksmaliOptions();
        opts.apiLevel = 29;
        opts.deodex = true;
        opts.classPath = new ClassPath(providers, true, oatVer);

        for (String entry : targetContainer.getDexEntryNames()) {
            DexFile df = targetContainer.getEntry(entry).getDexFile();
            if (!Baksmali.disassembleDexFile(df, outSmaliDir, 8, opts)) {
                throw new RuntimeException("Baksmali failed for " + entry);
            }
        }
    }
}
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_mapcon_inputs(
    emui_system_dir: Path, expected_sha256: dict[str, str] | None = None
) -> None:
    expected = EXPECTED_INPUT_SHA256 if expected_sha256 is None else expected_sha256
    for rel, exp_hash in expected.items():
        candidate = emui_system_dir / rel
        if not candidate.is_file():
            raise FileNotFoundError(f"Missing required .225 Mapcon input: {candidate}")
        actual = _sha256(candidate)
        if actual != exp_hash:
            raise ValueError(
                f"SHA-256 mismatch for {rel}: expected {exp_hash}, got {actual}"
            )


def _extract_apex_javalibs(emui_system_dir: Path, out_dir: Path) -> None:
    debugfs = shutil.which("debugfs") or "/usr/sbin/debugfs"
    if not Path(debugfs).is_file():
        raise FileNotFoundError("Missing host debugfs required to unpack .225 APEX javalibs")

    for apex_name in APEX_BOOT_ARCHIVES:
        apex_path = emui_system_dir / "apex" / apex_name
        if not apex_path.is_file():
            raise FileNotFoundError(f"Missing .225 APEX archive: {apex_path}")
        with tempfile.TemporaryDirectory(dir=out_dir) as sub_td:
            sub_p = Path(sub_td)
            payload = sub_p / "apex_payload.img"
            with zipfile.ZipFile(apex_path, "r") as zf:
                payload.write_bytes(zf.read("apex_payload.img"))
            dump_dir = sub_p / "javalib_dump"
            dump_dir.mkdir()
            subprocess.run(
                [debugfs, "-R", f"rdump /javalib {dump_dir}", str(payload)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for jar in sorted(dump_dir.rglob("*.jar")):
                shutil.copyfile(jar, out_dir / f"{apex_name}_{jar.name}")


def _replace_exact(text: str, old: str, new: str, expected_count: int, label: str) -> str:
    count = text.count(old)
    if count != expected_count:
        raise ValueError(
            f"Mapcon smali patch {label!r}: expected {expected_count} match(es), got {count}"
        )
    return text.replace(old, new)


def prune_dead_bundled_framework_classes(smali_dir: Path) -> int:
    removed = 0
    for sf in sorted(smali_dir.rglob("*.smali")):
        rel = sf.relative_to(smali_dir).as_posix()
        if rel.startswith("android/net/") and not rel.startswith("android/net/wifi/HwQoE/"):
            sf.unlink()
            removed += 1
        elif rel == "com/android/internal/telephony/IPhoneCallback.smali":
            sf.unlink()
            removed += 1
    if removed != 34:
        raise ValueError(
            f"Expected to prune 34 dead/duplicate bundled classes from Mapcon, pruned {removed}"
        )
    return removed


def apply_smali_patches(smali_dir: Path) -> None:
    # 1. Route Mapcon's VoWiFi gate property from vendor_rild_prop to telephony_config_prop
    #    (readable by radio domain in com.android.phone).
    common_d = smali_dir / "com/hisi/mapcon/common/d.smali"
    d_txt = common_d.read_text(encoding="utf-8")
    d_txt = _replace_exact(
        d_txt,
        'const-string v0, "ro.vendor.config.hw_vowifi"',
        'const-string v0, "ro.config.hw_vowifi"',
        1,
        "common.d.hw_vowifi_prop",
    )
    common_d.write_text(d_txt, encoding="utf-8")

    # 2. VowifiNetworkFactory (com/hisi/mapcon/e/e.smali) -> LegacyNetworkFactory + TelephonyNetworkSpecifier.
    vf = smali_dir / "com/hisi/mapcon/e/e.smali"
    vf_txt = vf.read_text(encoding="utf-8")
    vf_txt = _replace_exact(
        vf_txt,
        ".super Landroid/net/NetworkFactory;",
        ".super Lcom/huawei/ims/shim/LegacyNetworkFactory;",
        1,
        "VowifiNetworkFactory.super",
    )
    vf_txt = _replace_exact(
        vf_txt,
        "invoke-direct {p0, p1, p2, p3, p4}, Landroid/net/NetworkFactory;-><init>(Landroid/os/Looper;Landroid/content/Context;Ljava/lang/String;Landroid/net/NetworkCapabilities;)V",
        "invoke-direct {p0, p1, p2, p3, p4}, Lcom/huawei/ims/shim/LegacyNetworkFactory;-><init>(Landroid/os/Looper;Landroid/content/Context;Ljava/lang/String;Landroid/net/NetworkCapabilities;)V",
        1,
        "VowifiNetworkFactory.init",
    )
    vf_txt = _replace_exact(
        vf_txt,
        """\
.method private a(Landroid/net/NetworkSpecifier;)I
    .registers 5

    const-string p0, "VowifiNetworkFactory"

    const/4 v0, -0x1

    if-nez p1, :cond_b

    const-string p1, "specifier is null"

    :goto_7
    invoke-static {p0, p1}, Lcom/hisi/mapcon/common/a;->error(Ljava/lang/String;Ljava/lang/String;)V

    return v0

    :cond_b
    instance-of v1, p1, Landroid/net/StringNetworkSpecifier;

    if-eqz v1, :cond_2b

    :try_start_f
    nop

    nop

    iget-object p1, p1, Landroid/net/StringNetworkSpecifier;->specifier:Ljava/lang/String;

    invoke-static {p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result p0
    :try_end_17
    .catch Ljava/lang/NumberFormatException; {:try_start_f .. :try_end_17} :catch_18

    return p0

    :catch_18
    move-exception p1

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "NumberFormatException, e="

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    goto :goto_7

    :cond_2b
    return v0
.end method""",
        """\
.method private a(Landroid/net/NetworkSpecifier;)I
    .registers 2

    invoke-static {p1}, Lcom/huawei/ims/shim/MapconShim;->parseSubIdFromSpecifier(Landroid/net/NetworkSpecifier;)I

    move-result p0

    return p0
.end method""",
        1,
        "VowifiNetworkFactory.parseSubIdFromSpecifier",
    )
    vf_txt = _replace_exact(
        vf_txt,
        """\
    new-instance v1, Landroid/net/StringNetworkSpecifier;

    invoke-static {p2}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    move-result-object p2

    invoke-direct {v1, p2}, Landroid/net/StringNetworkSpecifier;-><init>(Ljava/lang/String;)V""",
        """\
    invoke-static {p2}, Lcom/huawei/ims/shim/MapconShim;->createSubIdSpecifier(I)Landroid/net/NetworkSpecifier;

    move-result-object v1""",
        1,
        "VowifiNetworkFactory.createSubIdSpecifier",
    )
    vf_txt = _replace_exact(
        vf_txt,
        "Landroid/net/NetworkAgent;->sendNetworkInfo(Landroid/net/NetworkInfo;)V",
        "Lcom/huawei/ims/shim/LegacyNetworkAgent;->sendNetworkInfo(Landroid/net/NetworkInfo;)V",
        2,
        "VowifiNetworkFactory.sendNetworkInfo",
    )
    vf_txt = _replace_exact(
        vf_txt,
        "Landroid/net/NetworkAgent;->sendNetworkCapabilities(Landroid/net/NetworkCapabilities;)V",
        "Lcom/huawei/ims/shim/LegacyNetworkAgent;->sendNetworkCapabilities(Landroid/net/NetworkCapabilities;)V",
        2,
        "VowifiNetworkFactory.sendNetworkCapabilities",
    )
    vf.write_text(vf_txt, encoding="utf-8")

    # 3. VowifiNetworkAgent (com/hisi/mapcon/e/d.smali) -> LegacyNetworkAgent.
    va = smali_dir / "com/hisi/mapcon/e/d.smali"
    va_txt = va.read_text(encoding="utf-8")
    va_txt = _replace_exact(
        va_txt,
        ".super Landroid/net/NetworkAgent;",
        ".super Lcom/huawei/ims/shim/LegacyNetworkAgent;",
        1,
        "VowifiNetworkAgent.super",
    )
    va_txt = _replace_exact(
        va_txt,
        "invoke-direct/range {p0 .. p8}, Landroid/net/NetworkAgent;-><init>(Landroid/os/Looper;Landroid/content/Context;Ljava/lang/String;Landroid/net/NetworkInfo;Landroid/net/NetworkCapabilities;Landroid/net/LinkProperties;ILandroid/net/NetworkMisc;)V",
        "invoke-direct/range {p0 .. p8}, Lcom/huawei/ims/shim/LegacyNetworkAgent;-><init>(Landroid/os/Looper;Landroid/content/Context;Ljava/lang/String;Landroid/net/NetworkInfo;Landroid/net/NetworkCapabilities;Landroid/net/LinkProperties;ILandroid/net/NetworkMisc;)V",
        1,
        "VowifiNetworkAgent.init",
    )
    va.write_text(va_txt, encoding="utf-8")

    # 4. MapconService -> register/unregister NetworkProvider + Dual-SIM coordinator lifecycle hook.
    ms = smali_dir / "com/hisi/mapcon/MapconService.smali"
    ms_txt = ms.read_text(encoding="utf-8")
    ms_txt = _replace_exact(
        ms_txt,
        "invoke-virtual {v0, v2}, Landroid/net/NetworkFactory;->setScoreFilter(I)V",
        "invoke-virtual {v0, v2}, Lcom/huawei/ims/shim/LegacyNetworkFactory;->setScoreFilter(I)V",
        1,
        "MapconService.setScoreFilter",
    )
    ms_txt = _replace_exact(
        ms_txt,
        "invoke-virtual {v2, p0, v0}, Landroid/net/ConnectivityManager;->registerNetworkFactory(Landroid/os/Messenger;Ljava/lang/String;)I",
        "invoke-static {v2, p0, v0}, Lcom/huawei/ims/shim/MapconShim;->registerNetworkFactory(Landroid/net/ConnectivityManager;Landroid/os/Messenger;Ljava/lang/String;)I",
        1,
        "MapconService.registerNetworkFactory",
    )
    ms_txt = _replace_exact(
        ms_txt,
        "invoke-virtual {v0, v1}, Landroid/net/ConnectivityManager;->unregisterNetworkFactory(Landroid/os/Messenger;)V",
        "invoke-static {v0, v1}, Lcom/huawei/ims/shim/MapconShim;->unregisterNetworkFactory(Landroid/net/ConnectivityManager;Landroid/os/Messenger;)V",
        1,
        "MapconService.unregisterNetworkFactory",
    )
    ms_txt = _replace_exact(
        ms_txt,
        "    sput-object v0, Lcom/hisi/mapcon/MapconService;->sContext:Landroid/content/Context;\n\n    invoke-direct {p0}, Lcom/hisi/mapcon/MapconService;->init()V",
        "    sput-object v0, Lcom/hisi/mapcon/MapconService;->sContext:Landroid/content/Context;\n\n    invoke-static {v0}, Lcom/huawei/ims/shim/MapconShim;->onServiceCreated(Landroid/content/Context;)V\n\n    invoke-direct {p0}, Lcom/hisi/mapcon/MapconService;->init()V",
        1,
        "MapconService.onCreate_onServiceCreated",
    )
    ms.write_text(ms_txt, encoding="utf-8")

    # 5. VoWifiQoeService + d.smali + WifiAdapter (adapter/x.smali) -> WifiInfo.getSnr + interrupt callback.
    qoe = smali_dir / "com/hisi/mapcon/vowifiqoe/VoWifiQoeService.smali"
    qoe_txt = qoe.read_text(encoding="utf-8")
    qoe_txt = _replace_exact(
        qoe_txt,
        "invoke-virtual {v0}, Landroid/net/wifi/WifiInfo;->getSnr()I",
        "invoke-static {v0}, Lcom/huawei/ims/shim/MapconShim;->getWifiSnr(Landroid/net/wifi/WifiInfo;)I",
        1,
        "VoWifiQoeService.getSnr",
    )
    qoe_txt = _replace_exact(
        qoe_txt,
        "Landroid/net/wifi/WifiManager$VoWifiSignalDetectInterruptCallback;",
        "Lcom/huawei/ims/shim/VoWifiSignalDetectInterruptCallback;",
        4,
        "VoWifiQoeService.VoWifiSignalDetectInterruptCallback",
    )
    qoe.write_text(qoe_txt, encoding="utf-8")

    qoe_d = smali_dir / "com/hisi/mapcon/vowifiqoe/d.smali"
    qd_txt = qoe_d.read_text(encoding="utf-8")
    qd_txt = _replace_exact(
        qd_txt,
        "Landroid/net/wifi/WifiManager$VoWifiSignalDetectInterruptCallback;",
        "Lcom/huawei/ims/shim/VoWifiSignalDetectInterruptCallback;",
        1,
        "vowifiqoe.d.VoWifiSignalDetectInterruptCallback",
    )
    qoe_d.write_text(qd_txt, encoding="utf-8")

    wifi_x = smali_dir / "com/hisi/mapcon/adapter/x.smali"
    wx_txt = wifi_x.read_text(encoding="utf-8")
    wx_txt = _replace_exact(
        wx_txt,
        "Landroid/net/wifi/WifiManager$VoWifiSignalDetectInterruptCallback;",
        "Lcom/huawei/ims/shim/VoWifiSignalDetectInterruptCallback;",
        3,
        "WifiAdapter.VoWifiSignalDetectInterruptCallback",
    )
    wifi_x.write_text(wx_txt, encoding="utf-8")

    # 6. FirmwareKeepAlive (com/hisi/mapcon/f/o.smali): Android 17 NattKeepalivePacketData throws
    #    android.net.InvalidPacketException rather than SocketKeepalive$InvalidPacketException.
    fka = smali_dir / "com/hisi/mapcon/f/o.smali"
    fka_txt = fka.read_text(encoding="utf-8")
    fka_txt = _replace_exact(
        fka_txt,
        "Landroid/net/SocketKeepalive$InvalidPacketException;",
        "Landroid/net/InvalidPacketException;",
        1,
        "FirmwareKeepAlive.InvalidPacketException",
    )
    fka.write_text(fka_txt, encoding="utf-8")

    # 7. UID-level SDK 31+/34+ CompatChanges in com.android.phone (SDK 37):
    #    - 15 PendingIntent.getBroadcast sites -> HwImsShim.getPendingIntentBroadcast
    #    - 10 Context/ContextWrapper.registerReceiver sites -> HwImsShim.registerReceiverCompat
    pi_bcast_count = 0
    reg_rcv_count = 0
    reg_3_re = re.compile(
        r"invoke-virtual \{([vp0-9, ]+)\}, Landroid/content/(?:Context|ContextWrapper);->registerReceiver\(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;\)Landroid/content/Intent;"
    )
    reg_5_re = re.compile(
        r"invoke-virtual \{([vp0-9, ]+)\}, Landroid/content/(?:Context|ContextWrapper);->registerReceiver\(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;\)Landroid/content/Intent;"
    )
    for sf in sorted(smali_dir.rglob("*.smali")):
        stxt = sf.read_text(encoding="utf-8")
        orig = stxt
        c_pi = stxt.count(
            "Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;"
        )
        if c_pi:
            stxt = stxt.replace(
                "Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;",
                "Lcom/huawei/ims/HwImsShim;->getPendingIntentBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;",
            )
            pi_bcast_count += c_pi
        stxt, c_r3 = reg_3_re.subn(
            r"invoke-static {\1}, Lcom/huawei/ims/HwImsShim;->registerReceiverCompat(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;",
            stxt,
        )
        stxt, c_r5 = reg_5_re.subn(
            r"invoke-static {\1}, Lcom/huawei/ims/HwImsShim;->registerReceiverCompat(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;",
            stxt,
        )
        reg_rcv_count += c_r3 + c_r5
        if stxt != orig:
            sf.write_text(stxt, encoding="utf-8")
        if (
            "Landroid/app/PendingIntent;->get" in stxt
            or "Landroid/content/Context;->registerReceiver(" in stxt
            or "Landroid/content/ContextWrapper;->registerReceiver(" in stxt
        ):
            raise ValueError(
                f"Unshimmed PendingIntent/registerReceiver call remained in {sf.relative_to(smali_dir)}"
            )
    if pi_bcast_count != 15:
        raise ValueError(f"Expected 15 Mapcon PendingIntent.getBroadcast sites, got {pi_bcast_count}")
    if reg_rcv_count != 10:
        raise ValueError(f"Expected 10 Mapcon registerReceiver sites, got {reg_rcv_count}")


def _write_deterministic_apk(
    orig_apk: Path,
    classes_dex: Path,
    classes2_dex: Path,
    jni_libs: dict[str, bytes],
    out_apk: Path,
) -> None:
    preserved: list[tuple[str, int, bytes]] = []
    with zipfile.ZipFile(orig_apk, "r") as zin:
        for info in zin.infolist():
            name = info.filename
            if (
                name.startswith("META-INF/")
                or name.startswith("lib/")
                or (name.startswith("classes") and name.endswith(".dex"))
                or name.endswith("/")
            ):
                continue
            compress_type = (
                zipfile.ZIP_STORED if name == "resources.arsc" else zipfile.ZIP_DEFLATED
            )
            preserved.append((name, compress_type, zin.read(name)))

    preserved.sort(key=lambda item: item[0])
    out_apk.parent.mkdir(parents=True, exist_ok=True)

    with open(out_apk, "wb") as raw_out:
        with zipfile.ZipFile(raw_out, "w") as zout:
            for name, ctype, data in preserved:
                zi = zipfile.ZipInfo(filename=name, date_time=FIXED_ZIP_DT)
                zi.compress_type = ctype
                zi.external_attr = 0o644 << 16
                if ctype == zipfile.ZIP_STORED:
                    header_len = 30 + len(name.encode("utf-8"))
                    pad = (4 - ((raw_out.tell() + header_len) % 4)) % 4
                    zi.extra = b"\x00" * pad
                zout.writestr(zi, data)

            for dex_name, dex_path in (
                ("classes.dex", classes_dex),
                ("classes2.dex", classes2_dex),
            ):
                zi = zipfile.ZipInfo(filename=dex_name, date_time=FIXED_ZIP_DT)
                zi.compress_type = zipfile.ZIP_STORED
                zi.external_attr = 0o644 << 16
                header_len = 30 + len(dex_name.encode("utf-8"))
                pad = (4 - ((raw_out.tell() + header_len) % 4)) % 4
                zi.extra = b"\x00" * pad
                zout.writestr(zi, dex_path.read_bytes())

            for lib_name in sorted(jni_libs):
                arcname = f"lib/arm64-v8a/{lib_name}"
                zi = zipfile.ZipInfo(filename=arcname, date_time=FIXED_ZIP_DT)
                zi.compress_type = zipfile.ZIP_STORED
                zi.external_attr = 0o644 << 16
                header_len = 30 + len(arcname.encode("utf-8"))
                pad = (
                    PAGE_ALIGN_BYTES
                    - ((raw_out.tell() + header_len) % PAGE_ALIGN_BYTES)
                ) % PAGE_ALIGN_BYTES
                zi.extra = b"\x00" * pad
                zout.writestr(zi, jni_libs[lib_name])


def build_patched_mapcon_apk(
    emui_system_dir: Path,
    android_root_dir: Path,
    shim_dir: Path,
    out_apk_path: Path,
) -> None:
    verify_mapcon_inputs(emui_system_dir)

    jdk_bin = android_root_dir / "prebuilts/jdk/jdk21/linux-x86/bin"
    javac = jdk_bin / "javac"
    java = jdk_bin / "java"
    r8_jar = android_root_dir / "prebuilts/r8/r8.jar"
    smali_jar = android_root_dir / "prebuilts/extract-tools/common/smali/smali.jar"
    ext_lib = android_root_dir / "prebuilts/cmdline-tools/tools/lib/external"
    modlib = android_root_dir / "prebuilts/sdk/current/module-lib"

    deodex_jars = [
        ext_lib / "com/android/tools/smali/smali-baksmali/3.0.9/smali-baksmali-3.0.9.jar",
        ext_lib / "com/android/tools/smali/smali-dexlib2/3.0.9/smali-dexlib2-3.0.9.jar",
        ext_lib / "com/android/tools/smali/smali-util/3.0.9/smali-util-3.0.9.jar",
        ext_lib / "com/google/guava/guava/33.3.1-jre/guava-33.3.1-jre.jar",
        ext_lib / "com/google/guava/failureaccess/1.0.2/failureaccess-1.0.2.jar",
    ]
    for required in (javac, java, r8_jar, smali_jar, *deodex_jars):
        if not required.is_file():
            raise FileNotFoundError(f"Missing required build prebuilt: {required}")

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        apex_jars_dir = tdp / "apex_jars"
        apex_jars_dir.mkdir()
        _extract_apex_javalibs(emui_system_dir, apex_jars_dir)

        helper_dir = tdp / "helper"
        helper_dir.mkdir()
        helper_src = helper_dir / "CleanDeodex.java"
        helper_src.write_text(CLEAN_DEODEX_JAVA, encoding="utf-8")
        deodex_cp = ":".join(str(p) for p in [helper_dir, *deodex_jars])
        subprocess.run(
            [
                str(javac),
                "--release",
                "11",
                "-cp",
                deodex_cp,
                "-d",
                str(helper_dir),
                str(helper_src),
            ],
            check=True,
        )

        oat_work = tdp / "oat"
        oat_work.mkdir()
        shutil.copyfile(
            emui_system_dir / "app/Mapcon/oat/arm64/Mapcon.odex", oat_work / "Mapcon.odex"
        )
        shutil.copyfile(
            emui_system_dir / "app/Mapcon/oat/arm64/Mapcon.vdex", oat_work / "Mapcon.vdex"
        )

        smali_dir = tdp / "smali"
        smali_dir.mkdir()
        subprocess.run(
            [
                str(java),
                "-cp",
                deodex_cp,
                "CleanDeodex",
                str(oat_work / "Mapcon.odex"),
                str(smali_dir),
                str(apex_jars_dir),
                str(emui_system_dir / "framework"),
                str(emui_system_dir / "framework/oat/arm64"),
            ],
            check=True,
        )

        all_smali = sorted(smali_dir.rglob("*.smali"))
        if len(all_smali) != 315:
            raise ValueError(f"Expected 315 deodexed Mapcon classes, got {len(all_smali)}")
        for sf in all_smali:
            content = sf.read_text(encoding="utf-8")
            if "disallowed odex opcode" in content or "#unresolved" in content:
                raise ValueError(
                    f"Unresolved odex opcode remained in {sf.relative_to(smali_dir)}"
                )

        prune_dead_bundled_framework_classes(smali_dir)
        apply_smali_patches(smali_dir)

        smali_files = sorted(smali_dir.rglob("*.smali"))
        if len(smali_files) != 281:
            raise ValueError(f"Expected 281 retained Mapcon classes, got {len(smali_files)}")

        classes_dex = tdp / "classes.dex"
        rel_smali_files = [str(p.relative_to(smali_dir)) for p in smali_files]
        subprocess.run(
            [
                str(java),
                "-jar",
                str(smali_jar),
                "a",
                "-j",
                "1",
                "-a",
                "29",
                *rel_smali_files,
                "-o",
                str(classes_dex),
            ],
            cwd=str(smali_dir),
            check=True,
        )

        stub_cls = tdp / "stub_cls"
        shim_cls = tdp / "shim_cls"
        dex2_dir = tdp / "dex2"
        stub_cls.mkdir()
        shim_cls.mkdir()
        dex2_dir.mkdir()
        cold_cp = (
            f"{modlib / 'android.jar'}:"
            f"{modlib / 'framework-connectivity.jar'}:"
            f"{modlib / 'framework-wifi.jar'}"
        )
        stubs = sorted(str(p) for p in (shim_dir / "compile_stubs").rglob("*.java"))
        srcs = sorted(str(p) for p in (shim_dir / "src").rglob("*.java"))
        subprocess.run(
            [str(javac), "--release", "11", "-cp", cold_cp, "-d", str(stub_cls), *stubs],
            check=True,
        )
        subprocess.run(
            [
                str(javac),
                "--release",
                "11",
                "-cp",
                f"{cold_cp}:{stub_cls}",
                "-d",
                str(shim_cls),
                *srcs,
            ],
            check=True,
        )
        cls_files = sorted(str(p) for p in shim_cls.rglob("*.class"))
        subprocess.run(
            [
                str(java),
                "-cp",
                str(r8_jar),
                "com.android.tools.r8.D8",
                "--min-api",
                "29",
                "--output",
                str(dex2_dir),
                *cls_files,
            ],
            check=True,
        )
        classes2_dex = dex2_dir / "classes.dex"
        jni_libs = {
            "libc_secshared.so": (emui_system_dir / "lib64/libc_secshared.so").read_bytes(),
            "libvowifiqoe.so": (emui_system_dir / "lib64/libvowifiqoe.so").read_bytes(),
        }

        _write_deterministic_apk(
            emui_system_dir / "app/Mapcon/Mapcon.apk",
            classes_dex,
            classes2_dex,
            jni_libs,
            out_apk_path,
        )


def _resolve_emui_system_dir() -> Path:
    env_dir = os.environ.get("BLANC_EMUI_SYSTEM_DIR")
    if env_dir:
        return Path(env_dir).resolve()

    frame = inspect.currentframe()
    try:
        while frame is not None:
            src_obj = frame.f_locals.get("source")
            dump_dir = getattr(src_obj, "_DiskSource__dump_dir", None)
            if dump_dir:
                cand = Path(dump_dir) / "system"
                if (cand / "app/Mapcon/Mapcon.apk").is_file():
                    return cand.resolve()
            frame = frame.f_back
    finally:
        del frame

    from extract_utils.args import parse_args

    src_arg = getattr(parse_args(), "source", None)
    if src_arg:
        cand = Path(src_arg) / "system"
        if (cand / "app/Mapcon/Mapcon.apk").is_file():
            return cand.resolve()

    raise FileNotFoundError(
        "Unable to locate .225 system directory for Mapcon rebuild; set BLANC_EMUI_SYSTEM_DIR"
    )


def _resolve_android_and_shim_dirs(module_dir: Path) -> tuple[Path, Path]:
    env_android = os.environ.get("BLANC_ANDROID_ROOT")
    if env_android:
        android_root = Path(env_android).resolve()
    else:
        try:
            from extract_utils.tools import android_root as eu_root

            android_root = Path(eu_root).resolve()
        except Exception:
            android_root = (module_dir / "../../..").resolve()

    env_shim = os.environ.get("BLANC_HUAWEI_IMS_SHIM_DIR")
    if env_shim:
        shim_dir = Path(env_shim).resolve()
    else:
        shim_dir = android_root / "hardware/huawei/ims/shim"
        if not (shim_dir / "src").is_dir():
            alt = (module_dir / "../packaging-hardware/ims/shim").resolve()
            if (alt / "src").is_dir():
                shim_dir = alt

    if not (shim_dir / "src").is_dir():
        raise FileNotFoundError(
            f"Missing hardware/huawei/ims/shim/src directory (checked {shim_dir})"
        )
    return android_root, shim_dir


def blob_fixup(ctx, file, file_path, *args, **kwargs):
    destination = Path(file_path)
    orig_sha256 = _sha256(destination)
    if orig_sha256 != EXPECTED_INPUT_SHA256["app/Mapcon/Mapcon.apk"]:
        raise ValueError(
            f"Mapcon.apk input SHA-256 mismatch: expected {EXPECTED_INPUT_SHA256['app/Mapcon/Mapcon.apk']}, got {orig_sha256}"
        )
    module_dir = Path(ctx.module_dir).resolve()
    emui_system_dir = _resolve_emui_system_dir()
    android_root, shim_dir = _resolve_android_and_shim_dirs(module_dir)
    build_patched_mapcon_apk(emui_system_dir, android_root, shim_dir, destination)
    print(
        f"BLA Mapcon.apk rebuilt deterministically: {orig_sha256} -> {_sha256(destination)}"
    )
