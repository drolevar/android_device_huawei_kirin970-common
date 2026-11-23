# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
"""Deterministically deodex, patch, shim, and repack .225 HwIms.apk for Android 17."""

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
    "app/HwIms/HwIms.apk": "6e97430b29197f2e7a2b211407c8a4ea7e40bb8d456071c1a061e72b5de54ae8",
    "app/HwIms/oat/arm64/HwIms.odex": "a7f89692ae7d193cdcea6931445ee3d35d1df4df5a561feed0077543e6d52b0b",
    "app/HwIms/oat/arm64/HwIms.vdex": "84cf2f18b512570ca0f64a7ae154dfaa3e2c8bbaaa7c738bcaf8575eebd94583",
    "app/HwIms/lib/arm64/libcrypto.so": "fc5d773d224daf3577f1ac273b7846f0332f0fd148fdf0081c0ab0b1516295b2",
    "app/HwIms/lib/arm64/libhw_media.so": "a79e784b0d68f0d1e6e431f69f2f002b1a09ddc8cbcb3ab79252e480bbae9c20",
    "app/HwIms/lib/arm64/libhw_sys.so": "17b1d49aeae2c38d39bf7a8186c79de3facbadd5a750e6490b855825fda350d5",
    "app/HwIms/lib/arm64/liblogin.so": "586e5fdcd804f3b75dc601e7394c34dee64554dd4e167fce46596ea820a4591f",
    "app/HwIms/lib/arm64/libmvd_hme_vt.so": "630e1cf5701d813726cdb26183f69cafd3c668f23498122362b404369479a06c",
    "app/HwIms/lib/arm64/libsci.so": "584343a789bbf1d62ad083778e2671425ab6e077d798f927713a25b9b57c9624",
    "app/HwIms/lib/arm64/libsci_ssconf.so": "19f8e75b53e99f432b3599648b0c00109268e077b2130a475a53bc3b21488277",
    "app/HwIms/lib/arm64/libsci_tls_default.so": "f225633e1c8f687dcc39844f668633af897ba12677c56be487ed1c6600948427",
    "app/HwIms/lib/arm64/libsecurec.so": "de2967893b84cb2bd52c3ac3b1da5907d763545661e228eb791c9a206113b695",
    "app/HwIms/lib/arm64/libssl.so": "d20728dad4961326394ef48b15d65350594ce6ca9bf5a356e814dc1c3b0cb513",
    "app/HwIms/lib/arm64/libtls_default.so": "a16a7afba6eba29f7e53aa340f44244fef80fd0c71fe58df8cf640a45cdf7a3e",
    "app/HwIms/lib/arm64/libut.so": "b310fab6cbe68ca7379e68b161c73ffb92825025dab36d9308af0bc8d19b74e7",
    "app/HwIms/lib/arm64/libvsc.so": "db0dbe9742ccc24fc397bb0945bc04d065de416cf10990cda8b096a87da9388f",
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


def verify_hwims_inputs(emui_system_dir: Path, expected_sha256: dict[str, str] | None = None) -> None:
    expected = EXPECTED_INPUT_SHA256 if expected_sha256 is None else expected_sha256
    for rel, exp_hash in expected.items():
        candidate = emui_system_dir / rel
        if not candidate.is_file():
            raise FileNotFoundError(f"Missing required .225 HwIms input: {candidate}")
        actual = _sha256(candidate)
        if actual != exp_hash:
            raise ValueError(
                f"SHA-256 mismatch for {rel}: expected {exp_hash}, got {actual}"
            )


def _replace_exact(text: str, old: str, new: str, expected_count: int, label: str) -> str:
    count = text.count(old)
    if count != expected_count:
        raise ValueError(
            f"HwIms smali patch {label!r}: expected {expected_count} match(es), got {count}"
        )
    return text.replace(old, new)


def _regex_sub_exact(
    text: str, pattern: str, repl: str, expected_count: int, label: str
) -> str:
    new_text, count = re.subn(pattern, repl, text, flags=re.MULTILINE)
    if count != expected_count:
        raise ValueError(
            f"HwIms smali regex patch {label!r}: expected {expected_count} match(es), got {count}"
        )
    return new_text


def apply_smali_patches(smali_dir: Path) -> None:
    # 1. Isolate OpenSSL 1.1 JNI library names from Android 17 BoringSSL/Conscrypt.
    sci_tls = smali_dir / "com/huawei/sci/SciDefaultTls.smali"
    txt = sci_tls.read_text(encoding="utf-8")
    txt = _replace_exact(txt, 'const-string v3, "ssl"', 'const-string v3, "ssl_hwims"', 1, "SciDefaultTls.ssl")
    txt = _replace_exact(txt, 'const-string v4, "crypto"', 'const-string v4, "crypto_hwims"', 1, "SciDefaultTls.crypto")
    txt = _replace_exact(txt, 'const-string v2, "/libcrypto.so"', 'const-string v2, "/libcrypto_hwims.so"', 1, "SciDefaultTls.libcrypto_path")
    txt = _replace_exact(txt, 'const-string v2, "/libssl.so"', 'const-string v2, "/libssl_hwims.so"', 1, "SciDefaultTls.libssl_path")
    sci_tls.write_text(txt, encoding="utf-8")

    # 1b. Route ImsCallProviderUtils VoWiFi gate property from vendor_default_prop
    #     (ro.vendor.config.hw_vowifi) to telephony_config_prop (ro.config.hw_vowifi).
    icpu = smali_dir / "com/huawei/ims/ImsCallProviderUtils.smali"
    icpu_txt = icpu.read_text(encoding="utf-8")
    icpu_txt = _replace_exact(
        icpu_txt,
        'const-string v1, "ro.vendor.config.hw_vowifi"',
        'const-string v1, "ro.config.hw_vowifi"',
        1,
        "ImsCallProviderUtils.hw_vowifi_prop",
    )
    icpu.write_text(icpu_txt, encoding="utf-8")

    # 2. Accept RIL_RADIO_TECHNOLOGY_LTE_CA (19 = 0x13) in isRadioTechnologyLteOrNr(I)Z,
    #    while preserving 18 (0x12 = IWLAN) false so VoWiFi reports REGISTRATION_TECH_IWLAN.
    handler = smali_dir / "com/huawei/ims/HwImsServiceImpl$HwImsServiceImplHandler.smali"
    htxt = handler.read_text(encoding="utf-8")
    htxt = _replace_exact(
        htxt,
        "    const/16 v0, 0xe\n\n    if-eq p1, v0, :cond_b\n\n    const/16 v0, 0x14",
        "    const/16 v0, 0xe\n\n    if-eq p1, v0, :cond_b\n\n    const/16 v0, 0x13\n\n    if-eq p1, v0, :cond_b\n\n    const/16 v0, 0x14",
        1,
        "HwImsServiceImplHandler.isRadioTechnologyLteOrNr_LTE_CA",
    )
    htxt = _replace_exact(
        htxt,
        "invoke-virtual {v1, v0}, Lcom/android/internal/telephony/AbstractPhoneBase;->setSpeechInfoCodec(I)V",
        "invoke-static {v1, v0}, Lcom/huawei/ims/HwImsShim;->setSpeechInfoCodec(Lcom/android/internal/telephony/Phone;I)V",
        1,
        "HwImsServiceImplHandler.setSpeechInfoCodec",
    )
    htxt = _replace_exact(
        htxt,
        "invoke-virtual {v1}, Lcom/android/internal/telephony/AbstractPhoneBase;->getSpeechInfoCodec()Ljava/lang/String;",
        "invoke-static {v1}, Lcom/huawei/ims/HwImsShim;->getSpeechInfoCodec(Lcom/android/internal/telephony/Phone;)Ljava/lang/String;",
        1,
        "HwImsServiceImplHandler.getSpeechInfoCodec",
    )
    handler.write_text(htxt, encoding="utf-8")

    # 3. Wire HwImsService lifecycle to vendor.huawei.hardware.radio@2.0::IRadio::setImsSwitch.
    svc = smali_dir / "com/huawei/ims/HwImsService.smali"
    stxt = svc.read_text(encoding="utf-8")
    stxt = _replace_exact(
        stxt,
        ".method public disableIms(I)V\n    .registers 2\n    .param p1, \"slotId\"    # I\n\n    .line 197\n    return-void\n.end method",
        ".method public disableIms(I)V\n    .registers 2\n    .param p1, \"slotId\"    # I\n\n    .line 197\n    invoke-static {p1}, Lcom/huawei/ims/HwImsShim;->disableModemImsSwitch(I)V\n\n    return-void\n.end method",
        1,
        "HwImsService.disableIms",
    )
    stxt = _replace_exact(
        stxt,
        ".method public enableIms(I)V\n    .registers 2\n    .param p1, \"slotId\"    # I\n\n    .line 193\n    return-void\n.end method",
        ".method public enableIms(I)V\n    .registers 2\n    .param p1, \"slotId\"    # I\n\n    .line 193\n    invoke-static {p1}, Lcom/huawei/ims/HwImsShim;->enableModemImsSwitch(I)V\n\n    return-void\n.end method",
        1,
        "HwImsService.enableIms",
    )
    stxt = _replace_exact(
        stxt,
        "    :cond_9c\n    goto :goto_a2",
        "    :cond_9c\n    invoke-static {p0}, Lcom/huawei/ims/HwImsShim;->onServiceCreated(Landroid/content/Context;)V\n\n    goto :goto_a2",
        1,
        "HwImsService.onCreate",
    )
    svc.write_text(stxt, encoding="utf-8")

    # 4. Patch HwImsServiceImpl telephony/CallManager/CommandsInterface bridges.
    impl = smali_dir / "com/huawei/ims/HwImsServiceImpl.smali"
    itxt = impl.read_text(encoding="utf-8")
    itxt = _replace_exact(
        itxt,
        "invoke-static {}, Lcom/android/internal/telephony/CallManager;->getInstance()Lcom/android/internal/telephony/CallManager;",
        "invoke-static {}, Lcom/huawei/ims/HwImsShim;->getCallManager()Lcom/android/internal/telephony/CallManager;",
        1,
        "HwImsServiceImpl.CallManager_getInstance",
    )
    itxt = _replace_exact(
        itxt,
        "invoke-virtual {v0, v2, v3, v1}, Lcom/android/internal/telephony/CallManager;->registerForNewRingingConnection(Landroid/os/Handler;ILjava/lang/Object;)V",
        "invoke-static {v0, v2, v3, v1}, Lcom/huawei/ims/HwImsShim;->registerForNewRingingConnection(Lcom/android/internal/telephony/CallManager;Landroid/os/Handler;ILjava/lang/Object;)V",
        1,
        "HwImsServiceImpl.registerForNewRingingConnection",
    )
    itxt = _replace_exact(
        itxt,
        "invoke-interface {v0, v2, v3, v1}, Lcom/android/internal/telephony/CommandsInterface;->registerForUnsolNvCfgFinished(Landroid/os/Handler;ILjava/lang/Object;)V",
        "invoke-static {v0, v2, v3, v1}, Lcom/huawei/ims/HwImsShim;->registerForUnsolNvCfgFinished(Lcom/android/internal/telephony/CommandsInterface;Landroid/os/Handler;ILjava/lang/Object;)V",
        1,
        "HwImsServiceImpl.registerForUnsolNvCfgFinished",
    )
    itxt = _replace_exact(
        itxt,
        "invoke-virtual {v0, p1}, Landroid/telephony/TelephonyManager;->getCurrentPhoneTypeForSlot(I)I",
        "invoke-static {v0, p1}, Lcom/huawei/ims/HwImsShim;->getCurrentPhoneTypeForSlot(Landroid/telephony/TelephonyManager;I)I",
        1,
        "HwImsServiceImpl.getCurrentPhoneTypeForSlot",
    )
    itxt = _replace_exact(
        itxt,
        "invoke-virtual {v0}, Lcom/android/internal/telephony/AbstractPhoneBase;->getImsSwitch()Z",
        "invoke-static {v0}, Lcom/huawei/ims/HwImsShim;->getImsSwitch(Lcom/android/internal/telephony/Phone;)Z",
        1,
        "HwImsServiceImpl.getImsSwitch",
    )
    itxt = _replace_exact(
        itxt,
        "invoke-virtual {p1}, Lcom/android/internal/telephony/Phone;->getTransportManager()Lcom/android/internal/telephony/dataconnection/TransportManager;",
        "invoke-static {p1}, Lcom/huawei/ims/HwImsShim;->getTransportManager(Lcom/android/internal/telephony/Phone;)Lcom/android/internal/telephony/dataconnection/TransportManager;",
        4,
        "HwImsServiceImpl.getTransportManager",
    )
    itxt = _replace_exact(
        itxt,
        "invoke-interface {v0, v1}, Lcom/android/internal/telephony/CommandsInterface;->unregisterForSrvccStateChanged(Landroid/os/Handler;)V",
        "invoke-static {v0, v1}, Lcom/huawei/ims/HwImsShim;->unregisterForSrvccStateChanged(Lcom/android/internal/telephony/CommandsInterface;Landroid/os/Handler;)V",
        1,
        "HwImsServiceImpl.unregisterForSrvccStateChanged",
    )
    itxt = _replace_exact(
        itxt,
        "invoke-interface {v0, p1, v1}, Lcom/android/internal/telephony/CommandsInterface;->setVoNrSwitch(ILandroid/os/Message;)V",
        "invoke-static {v0, p1, v1}, Lcom/huawei/ims/HwImsShim;->setVoNrSwitch(Lcom/android/internal/telephony/CommandsInterface;ILandroid/os/Message;)V",
        1,
        "HwImsServiceImpl.setVoNrSwitch",
    )
    impl.write_text(itxt, encoding="utf-8")

    # 5. Patch HwImsUtImpl bridges.
    ut = smali_dir / "com/huawei/ims/HwImsUtImpl.smali"
    utxt = ut.read_text(encoding="utf-8")
    utxt = _replace_exact(
        utxt,
        "invoke-virtual/range {v1 .. v6}, Landroid/net/ConnectivityManager;->requestNetwork(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;IILandroid/os/Handler;)V",
        "invoke-static/range {v1 .. v6}, Lcom/huawei/ims/HwImsShim;->requestNetwork(Landroid/net/ConnectivityManager;Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;IILandroid/os/Handler;)V",
        2,
        "HwImsUtImpl.requestNetwork",
    )
    utxt = _replace_exact(
        utxt,
        "iget-object v1, v2, Lcom/android/internal/telephony/GsmCdmaPhone;->mHwGsmCdmaPhoneEx:Lcom/android/internal/telephony/IHwGsmCdmaPhoneEx;",
        "invoke-static {v2}, Lcom/huawei/ims/HwImsShim;->getHwGsmCdmaPhoneEx(Lcom/android/internal/telephony/Phone;)Lcom/android/internal/telephony/IHwGsmCdmaPhoneEx;\n\n    move-result-object v1",
        1,
        "HwImsUtImpl.mHwGsmCdmaPhoneEx",
    )
    utxt = _replace_exact(
        utxt,
        "invoke-virtual {p1, v1, v2, p3}, Lcom/android/internal/telephony/AbstractPhoneBase;->getCallForwardingOption(IILandroid/os/Message;)V",
        "invoke-static {p1, v1, v2, p3}, Lcom/huawei/ims/HwImsShim;->getCallForwardingOption(Lcom/android/internal/telephony/Phone;IILandroid/os/Message;)V",
        1,
        "HwImsUtImpl.getCallForwardingOption",
    )
    utxt = _replace_exact(
        utxt,
        "invoke-virtual/range {v2 .. v7}, Lcom/android/internal/telephony/AbstractPhoneBase;->setCallbarringOption(Ljava/lang/String;Ljava/lang/String;ZILandroid/os/Message;)V",
        "invoke-static/range {v2 .. v7}, Lcom/huawei/ims/HwImsShim;->setCallbarringOption(Lcom/android/internal/telephony/Phone;Ljava/lang/String;Ljava/lang/String;ZILandroid/os/Message;)V",
        1,
        "HwImsUtImpl.setCallbarringOption",
    )
    utxt = _replace_exact(
        utxt,
        "invoke-virtual {p1, v1, v2, p3}, Lcom/android/internal/telephony/AbstractPhoneBase;->getCallbarringOption(Ljava/lang/String;ILandroid/os/Message;)V",
        "invoke-static {p1, v1, v2, p3}, Lcom/huawei/ims/HwImsShim;->getCallbarringOption(Lcom/android/internal/telephony/Phone;Ljava/lang/String;ILandroid/os/Message;)V",
        1,
        "HwImsUtImpl.getCallbarringOption",
    )
    utxt = _replace_exact(
        utxt,
        "invoke-virtual {v6, v7}, Landroid/net/NetworkSpecifier;->satisfiedBy(Landroid/net/NetworkSpecifier;)Z",
        "invoke-static {v6, v7}, Lcom/huawei/ims/HwImsShim;->satisfiedBy(Landroid/net/NetworkSpecifier;Landroid/net/NetworkSpecifier;)Z",
        1,
        "HwImsUtImpl.satisfiedBy",
    )
    utxt = _replace_exact(
        utxt,
        "invoke-virtual {v0}, Lcom/android/internal/telephony/AbstractPhoneBase;->getImsSwitch()Z",
        "invoke-static {v0}, Lcom/huawei/ims/HwImsShim;->getImsSwitch(Lcom/android/internal/telephony/Phone;)Z",
        1,
        "HwImsUtImpl.getImsSwitch",
    )
    utxt = _replace_exact(
        utxt,
        "iget-object v2, v1, Lcom/android/internal/telephony/imsphone/ImsPhone;->mHwImsPhoneEx:Lcom/android/internal/telephony/imsphone/IHwImsPhoneEx;",
        "invoke-static {v1}, Lcom/huawei/ims/HwImsShim;->getHwImsPhoneEx(Lcom/android/internal/telephony/Phone;)Lcom/android/internal/telephony/imsphone/IHwImsPhoneEx;\n\n    move-result-object v2",
        1,
        "HwImsUtImpl.mHwImsPhoneEx",
    )
    utxt = _replace_exact(
        utxt,
        "invoke-virtual {v2, v3}, Lcom/android/internal/telephony/imsphone/ImsPhone;->notifyECTFailed(Lcom/android/internal/telephony/PhoneInternalInterface$SuppService;)V",
        "invoke-static {v2, v3}, Lcom/huawei/ims/HwImsShim;->notifyECTFailed(Lcom/android/internal/telephony/imsphone/ImsPhone;Lcom/android/internal/telephony/PhoneInternalInterface$SuppService;)V",
        1,
        "HwImsUtImpl.notifyECTFailed",
    )
    utxt = _replace_exact(
        utxt,
        "invoke-virtual {v2, v3}, Lcom/android/internal/telephony/AbstractPhoneBase;->notifySuppServiceSuccessed(Lcom/android/internal/telephony/PhoneInternalInterface$SuppService;)V",
        "invoke-static {v2, v3}, Lcom/huawei/ims/HwImsShim;->notifySuppServiceSuccessed(Lcom/android/internal/telephony/Phone;Lcom/android/internal/telephony/PhoneInternalInterface$SuppService;)V",
        1,
        "HwImsUtImpl.notifySuppServiceSuccessed",
    )
    utxt = _regex_sub_exact(
        utxt,
        r"^([ \t]*)iput (\w+), (\w+), Landroid/telephony/ims/ImsCallForwardInfo;->m(StartHour|StartMinute|EndHour|EndMinute):I$",
        r"\1invoke-static {\3, \2}, Lcom/huawei/ims/HwImsShim;->set\4(Landroid/telephony/ims/ImsCallForwardInfo;I)V",
        8,
        "HwImsUtImpl.ImsCallForwardInfo_iput",
    )
    utxt = _regex_sub_exact(
        utxt,
        r"^([ \t]*)iget (\w+), (\w+), Landroid/telephony/ims/ImsCallForwardInfo;->m(StartHour|StartMinute|EndHour|EndMinute):I$",
        r"\1invoke-static {\3}, Lcom/huawei/ims/HwImsShim;->get\4(Landroid/telephony/ims/ImsCallForwardInfo;)I\n\n\1move-result \2",
        4,
        "HwImsUtImpl.ImsCallForwardInfo_iget",
    )
    ut.write_text(utxt, encoding="utf-8")

    # 6. Patch ImsRIL, ImsRadioIndication, MtStatusManager, and P2pTransportManager.
    ril = smali_dir / "com/huawei/ims/ImsRIL.smali"
    rtxt = ril.read_text(encoding="utf-8")
    rtxt = _replace_exact(
        rtxt,
        "    iget-object v1, p0, Lcom/android/internal/telephony/BaseCommands;->mExitEmergencyCallbackModeRegistrants:Landroid/os/RegistrantList;\n\n"
        "    if-eqz v1, :cond_2d\n\n"
        "    .line 3469\n"
        "    iget-object v1, p0, Lcom/android/internal/telephony/BaseCommands;->mExitEmergencyCallbackModeRegistrants:Landroid/os/RegistrantList;\n\n"
        "    invoke-virtual {v1}, Landroid/os/RegistrantList;->notifyRegistrants()V",
        "    invoke-static {p0}, Lcom/huawei/ims/HwImsShim;->notifyExitEmergencyCallbackModeRegistrants(Lcom/android/internal/telephony/BaseCommands;)V",
        1,
        "ImsRIL.mExitEmergencyCallbackModeRegistrants",
    )
    rtxt = _replace_exact(
        rtxt,
        "invoke-super {p0, p1}, Lcom/android/internal/telephony/BaseCommands;->unregisterForExitEmergencyCallbackMode(Landroid/os/Handler;)V",
        "invoke-static {p0, p1}, Lcom/huawei/ims/HwImsShim;->unregisterForExitEmergencyCallbackMode(Lcom/android/internal/telephony/BaseCommands;Landroid/os/Handler;)V",
        1,
        "ImsRIL.unregisterForExitEmergencyCallbackMode",
    )
    ril.write_text(rtxt, encoding="utf-8")

    ind = smali_dir / "com/huawei/ims/ImsRadioIndication.smali"
    ind_txt = ind.read_text(encoding="utf-8")
    ind_txt = _replace_exact(
        ind_txt,
        "invoke-virtual {v1, v0}, Lcom/android/internal/telephony/AbstractBaseCommands;->recordVoiceBandInfo([I)V",
        "invoke-static {v1, v0}, Lcom/huawei/ims/HwImsShim;->recordVoiceBandInfo(Ljava/lang/Object;[I)V",
        1,
        "ImsRadioIndication.recordVoiceBandInfo",
    )
    ind.write_text(ind_txt, encoding="utf-8")

    mt = smali_dir / "com/huawei/ims/MtStatusManager.smali"
    mtxt = mt.read_text(encoding="utf-8")
    mtxt = _replace_exact(
        mtxt,
        "iget-object v1, v0, Lcom/android/internal/telephony/imsphone/ImsPhone;->mHwImsPhoneEx:Lcom/android/internal/telephony/imsphone/IHwImsPhoneEx;",
        "invoke-static {v0}, Lcom/huawei/ims/HwImsShim;->getHwImsPhoneEx(Lcom/android/internal/telephony/Phone;)Lcom/android/internal/telephony/imsphone/IHwImsPhoneEx;\n\n    move-result-object v1",
        1,
        "MtStatusManager.mHwImsPhoneEx",
    )
    mt.write_text(mtxt, encoding="utf-8")

    p2p_ad = smali_dir / "com/huawei/ims/p2ptransport/P2pTransportManager$P2pTransportAdapter.smali"
    p2p_ad_txt = p2p_ad.read_text(encoding="utf-8")
    p2p_ad_txt = _replace_exact(
        p2p_ad_txt,
        "invoke-static {p2}, Lcom/android/internal/telephony/RIL;->arrayListToPrimitiveArray(Ljava/util/ArrayList;)[B",
        "invoke-static {p2}, Lcom/huawei/ims/HwImsShim;->arrayListToPrimitiveArray(Ljava/util/ArrayList;)[B",
        1,
        "P2pTransportAdapter.arrayListToPrimitiveArray",
    )
    p2p_ad.write_text(p2p_ad_txt, encoding="utf-8")

    p2p = smali_dir / "com/huawei/ims/p2ptransport/P2pTransportManager.smali"
    p2p_txt = p2p.read_text(encoding="utf-8")
    p2p_txt = _replace_exact(
        p2p_txt,
        "invoke-static {p2}, Lcom/android/internal/telephony/RIL;->primitiveArrayToArrayList([B)Ljava/util/ArrayList;",
        "invoke-static {p2}, Lcom/huawei/ims/HwImsShim;->primitiveArrayToArrayList([B)Ljava/util/ArrayList;",
        1,
        "P2pTransportManager.primitiveArrayToArrayList",
    )
    p2p.write_text(p2p_txt, encoding="utf-8")


def _extract_apex_javalibs(emui_system_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    debugfs = shutil.which("debugfs") or "/usr/sbin/debugfs"
    if not Path(debugfs).is_file():
        raise FileNotFoundError("debugfs is required to unpack .225 APEX bootclasspath jars")

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


def build_patched_hwims_apk(
    emui_system_dir: Path,
    android_root_dir: Path,
    shim_dir: Path,
    out_apk_path: Path,
) -> None:
    verify_hwims_inputs(emui_system_dir)

    jdk_bin = android_root_dir / "prebuilts/jdk/jdk21/linux-x86/bin"
    javac = jdk_bin / "javac"
    java = jdk_bin / "java"
    r8_jar = android_root_dir / "prebuilts/r8/r8.jar"
    smali_jar = android_root_dir / "prebuilts/extract-tools/common/smali/smali.jar"
    patchelf = android_root_dir / "prebuilts/extract-tools/linux-x86/bin/patchelf-0_18"
    ext_lib = android_root_dir / "prebuilts/cmdline-tools/tools/lib/external"
    modlib = android_root_dir / "prebuilts/sdk/current/module-lib"

    deodex_jars = [
        ext_lib / "com/android/tools/smali/smali-baksmali/3.0.9/smali-baksmali-3.0.9.jar",
        ext_lib / "com/android/tools/smali/smali-dexlib2/3.0.9/smali-dexlib2-3.0.9.jar",
        ext_lib / "com/android/tools/smali/smali-util/3.0.9/smali-util-3.0.9.jar",
        ext_lib / "com/google/guava/guava/33.3.1-jre/guava-33.3.1-jre.jar",
        ext_lib / "com/google/guava/failureaccess/1.0.2/failureaccess-1.0.2.jar",
    ]
    for required in (javac, java, r8_jar, smali_jar, patchelf, *deodex_jars):
        if not required.is_file():
            raise FileNotFoundError(f"Missing required build prebuilt: {required}")

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        apex_jars_dir = tdp / "apex_jars"
        _extract_apex_javalibs(emui_system_dir, apex_jars_dir)

        helper_dir = tdp / "helper"
        helper_dir.mkdir()
        helper_src = helper_dir / "CleanDeodex.java"
        helper_src.write_text(CLEAN_DEODEX_JAVA, encoding="utf-8")
        deodex_cp = ":".join(str(p) for p in [helper_dir, *deodex_jars])
        subprocess.run(
            [str(javac), "--release", "11", "-cp", deodex_cp, "-d", str(helper_dir), str(helper_src)],
            check=True,
        )

        # Copy HwIms.odex + HwIms.vdex side-by-side so dexlib2 OatFile locates the paired vdex.
        oat_work = tdp / "oat"
        oat_work.mkdir()
        shutil.copyfile(emui_system_dir / "app/HwIms/oat/arm64/HwIms.odex", oat_work / "HwIms.odex")
        shutil.copyfile(emui_system_dir / "app/HwIms/oat/arm64/HwIms.vdex", oat_work / "HwIms.vdex")

        smali_dir = tdp / "smali"
        smali_dir.mkdir()
        subprocess.run(
            [
                str(java),
                "-cp",
                deodex_cp,
                "CleanDeodex",
                str(oat_work / "HwIms.odex"),
                str(smali_dir),
                str(apex_jars_dir),
                str(emui_system_dir / "framework"),
                str(emui_system_dir / "framework/oat/arm64"),
            ],
            check=True,
        )

        smali_files = sorted(smali_dir.rglob("*.smali"))
        if len(smali_files) != 387:
            raise ValueError(f"Expected 387 deodexed HwIms classes, got {len(smali_files)}")
        for sf in smali_files:
            content = sf.read_text(encoding="utf-8")
            if "disallowed odex opcode" in content or "#unresolved" in content:
                raise ValueError(f"Unresolved odex opcode remained in {sf.relative_to(smali_dir)}")

        apply_smali_patches(smali_dir)

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

        # Compile huawei-ims-shim sources to classes2.dex deterministically.
        stub_cls = tdp / "stub_cls"
        shim_cls = tdp / "shim_cls"
        dex2_dir = tdp / "dex2"
        stub_cls.mkdir()
        shim_cls.mkdir()
        dex2_dir.mkdir()
        cold_cp = f"{modlib / 'android.jar'}:{modlib / 'framework-connectivity.jar'}"
        stubs = sorted(str(p) for p in (shim_dir / "compile_stubs").rglob("*.java"))
        srcs = sorted(str(p) for p in (shim_dir / "src").rglob("*.java"))
        subprocess.run(
            [str(javac), "--release", "11", "-cp", cold_cp, "-d", str(stub_cls), *stubs],
            check=True,
        )
        subprocess.run(
            [str(javac), "--release", "11", "-cp", f"{cold_cp}:{stub_cls}", "-d", str(shim_cls), *srcs],
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

        # Stage and isolate OpenSSL 1.1 SONAME/NEEDED across the 13 arm64 JNI libs.
        lib_work = tdp / "libs"
        lib_work.mkdir()
        for src_so in sorted((emui_system_dir / "app/HwIms/lib/arm64").glob("*.so")):
            dst_name = {
                "libcrypto.so": "libcrypto_hwims.so",
                "libssl.so": "libssl_hwims.so",
            }.get(src_so.name, src_so.name)
            shutil.copyfile(src_so, lib_work / dst_name)

        subprocess.run(
            [str(patchelf), "--set-soname", "libcrypto_hwims.so", str(lib_work / "libcrypto_hwims.so")],
            check=True,
        )
        subprocess.run(
            [
                str(patchelf),
                "--set-soname",
                "libssl_hwims.so",
                "--replace-needed",
                "libcrypto.so.1.1",
                "libcrypto_hwims.so",
                str(lib_work / "libssl_hwims.so"),
            ],
            check=True,
        )
        for consumer in ("libtls_default.so", "libsci_tls_default.so"):
            subprocess.run(
                [
                    str(patchelf),
                    "--replace-needed",
                    "libcrypto.so.1.1",
                    "libcrypto_hwims.so",
                    "--replace-needed",
                    "libssl.so.1.1",
                    "libssl_hwims.so",
                    str(lib_work / consumer),
                ],
                check=True,
            )

        jni_libs = {p.name: p.read_bytes() for p in sorted(lib_work.glob("*.so"))}
        if len(jni_libs) != 13:
            raise ValueError(f"Expected 13 HwIms JNI libraries, got {len(jni_libs)}")

        _write_deterministic_apk(
            emui_system_dir / "app/HwIms/HwIms.apk",
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
                if (cand / "app/HwIms/HwIms.apk").is_file():
                    return cand.resolve()
            frame = frame.f_back
    finally:
        del frame

    from extract_utils.args import parse_args

    src_arg = getattr(parse_args(), "source", None)
    if src_arg:
        cand = Path(src_arg) / "system"
        if (cand / "app/HwIms/HwIms.apk").is_file():
            return cand.resolve()

    raise FileNotFoundError(
        "Unable to locate .225 system directory for HwIms rebuild; set BLANC_EMUI_SYSTEM_DIR"
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
    if orig_sha256 != EXPECTED_INPUT_SHA256["app/HwIms/HwIms.apk"]:
        raise ValueError(
            f"HwIms.apk input SHA-256 mismatch: expected {EXPECTED_INPUT_SHA256['app/HwIms/HwIms.apk']}, got {orig_sha256}"
        )
    module_dir = Path(ctx.module_dir).resolve()
    emui_system_dir = _resolve_emui_system_dir()
    android_root, shim_dir = _resolve_android_and_shim_dirs(module_dir)
    build_patched_hwims_apk(emui_system_dir, android_root, shim_dir, destination)
    print(
        f"BLA HwIms.apk rebuilt deterministically: {orig_sha256} -> {_sha256(destination)}"
    )
