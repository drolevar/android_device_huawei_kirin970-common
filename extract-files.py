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
        .replace_needed('libui.so', 'libui-v29.so')
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
