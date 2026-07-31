#!/usr/bin/env -S PYTHONPATH=../../../tools/extract-utils python3
#
# SPDX-FileCopyrightText: The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

from extract_utils.fixups_blob import (
    blob_fixup,
    blob_fixups_user_type,
)
from extract_utils.fixups_lib import (
    lib_fixups,
)
from extract_utils.main import (
    ExtractUtils,
    ExtractUtilsModule,
)

namespace_imports = [
    'hardware/huawei',
]

blob_fixups: blob_fixups_user_type = {
    'vendor/etc/init/android.hardware.drm@1.2-service.widevine.rc': blob_fixup()
        .regex_replace(r'preavs', 'vendor'),
    'vendor/etc/init/vendor.huawei.hardware.biometrics.fingerprint@2.2-service.rc': blob_fixup()
        .regex_replace(
            r'    interface vendor\.huawei\.hardware\.biometrics\.fingerprint@2\.2::IExtBiometricsFingerprint default',
            r'    interface android.hardware.biometrics.fingerprint@2.1::IBiometricsFingerprint default\n'
            r'    interface vendor.huawei.hardware.biometrics.fingerprint@2.1::IExtBiometricsFingerprint default\n'
            r'    interface vendor.huawei.hardware.biometrics.fingerprint@2.2::IExtBiometricsFingerprint default',
        ),
    'vendor/etc/init/rild.rc': blob_fixup()
        .regex_replace(
            r'(service vendor\.ril-daemon /vendor/bin/hw/rild)',
            r'on property:sys.rilprops_ready=1\n    start vendor.ril-daemon\n\n\1',
        )
       .regex_replace(
            r'(\n    capabilities BLOCK_SUSPEND NET_ADMIN NET_RAW)',
            r'\1\n    disabled',
        ),
    (
        'vendor/lib64/hw/hwcomposer.kirin970.so',
        'vendor/lib/hw/hwcomposer.kirin970.so',
    ): blob_fixup()
        .replace_needed('libui.so', 'libui-v29.so'),
    (
        'vendor/lib64/libhiview.so',
        'vendor/lib/libhiview.so',
    ): blob_fixup()
        .replace_needed('libjsoncpp.so', 'libjsoncpp-v30.so'),
    'vendor/lib64/libSmartAE.so': blob_fixup()
        .sig_replace('9F 02 0A B9', '1F 20 03 D5'),
    (
        'vendor/lib64/libBestShot.so',
        'vendor/lib64/libDocBeauty.so',
        'vendor/lib64/libFNFD.so',
        'vendor/lib64/libFNFFD.so',
        'vendor/lib64/libFNFR.so',
        'vendor/lib64/libFaceBeautyMeiwo.so',
        'vendor/lib64/libHW_BShutter.so',
        'vendor/lib64/libHW_BShutterRaw.so',
        'vendor/lib64/libHwDocDetection.so',
        'vendor/lib64/libLaserSelfCali.so',
        'vendor/lib64/libOpenCLFoundation.so',
        'vendor/lib64/libSR_opencl.so',
        'vendor/lib64/libSmartAE.so',
        'vendor/lib64/libVideoDenoise.so',
        'vendor/lib64/libdcamera_disptodepth.so',
        'vendor/lib64/libfairlight.so',
        'vendor/lib64/libfairlight_ai.so',
        'vendor/lib64/libfairlight_ipu.so',
        'vendor/lib64/libhdr.so',
        'vendor/lib64/libhiview.so',
        'vendor/lib64/libimedia_filters.so',
        'vendor/lib64/libipu.so',
        'vendor/lib64/libmorpho_effect_library5.so',
        'vendor/lib64/libmotionEstimation.so',
        'vendor/lib64/libmrc_cg_ldc.so',
        'vendor/lib64/libmrc_cg_niceFood.so',
        'vendor/lib64/libmrc_cg_postprocess.so',
        'vendor/lib64/librawhdr.so',
        'vendor/lib64/libtrans_depth_code.so',
        'vendor/lib64/libvenuscropimageface.so',
    ): blob_fixup()
        .replace_needed('libstdc++.so', 'libstdc++_vendor.so'),
    (
        'vendor/lib/libOMX.hisi.media.common.so',
        'vendor/lib64/libOMX.hisi.media.common.so',
    ): blob_fixup()
        .add_needed('libui_shim.so'),
    (
        'vendor/lib/egl/libGLES_mali.so',
        'vendor/lib64/egl/libGLES_mali.so',
    ): blob_fixup()
        .clear_symbol_version('AHardwareBuffer_acquire')
        .clear_symbol_version('AHardwareBuffer_allocate')
        .clear_symbol_version('AHardwareBuffer_describe')
        .clear_symbol_version('AHardwareBuffer_getNativeHandle')
        .clear_symbol_version('AHardwareBuffer_release'),
    'vendor/lib64/libdcamera_effect.so': blob_fixup()
        .add_needed('liblog.so'),
}  # fmt: skip

module = ExtractUtilsModule(
    'kirin970-common',
    'huawei',
    blob_fixups=blob_fixups,
    lib_fixups=lib_fixups,
    namespace_imports=namespace_imports,
)

if __name__ == '__main__':
    utils = ExtractUtils.device(module)
    utils.run()
