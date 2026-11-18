# Exact stock filenames for the three Kirin 970 security services

Huawei `.225` TrustedCore (`/vendor/bin/teecd`) and TEEOS (`native_packages.xml`
plus signed `.sec` TA allowlists) authenticate native CA callers using their
literal `/proc/<pid>/cmdline` executable path. Disassembly of `vendor/bin/teecd`
(`0x97b4..0x981c`) reads `/proc/%d/cmdline` directly and rejects suffixed paths
such as `/vendor/bin/hw/android.hardware.keymaster@3.0-service.hisi`, stalling
`vold` FBE `installkey /data` on `/data/unencrypted/temp` before `keymaster_key_blob`.

Earlier extraction workarounds used `;MODULE=...service.hisi` + `:...service.hisi`
and `fixups/hisi_services.py`, which changed `/proc/<pid>/cmdline` and prevented
Soong `PrebuiltMutator` from pairing with same-named AOSP `cc_binary` modules.
Restoring the exact unsuffixed `.225` filenames and `.rc` files in
`proprietary-files.txt` generates same-name `cc_prebuilt_binary` definitions with
`prefer: true`, `relative_install_path: "hw"`, and `soc_specific: true`
(matching `rild`). Soong's `PrebuiltMutator` replaces any same-named AOSP source
module (`HideFromMake()` + `SkipInstall()`), keeping `/vendor/bin/hw/...` and
`/vendor/etc/init/...` byte-identical to stock `.225`.

## SELinux labels

AOSP `system/sepolicy/vendor/file_contexts` already maps all three exact
unsuffixed paths (`/vendor/bin/hw/android.hardware.{gatekeeper@1.0,keymaster@3.0,secure_element@1.0}-service`)
to their required `hal_{gatekeeper,keymaster,secure_element}_default_exec` types,
matching the `u:r:hal_keymaster_default:s0`, `u:r:hal_gatekeeper_default:s0`,
and `u:r:hal_secure_element_default:s0` domain transitions.

## Verification

`tests/test_service_names.py` verifies `proprietary-files.txt`, absence of
`.hisi` overrides, exact AOSP `file_contexts` resolution, and (when
`BLA_ORIGINAL_FILESYSTEMS` / `BLA_EXTRACTED_VENDOR` are set) byte-identical
stock ELFs and `.rc` files plus same-name `prefer: true` Soong modules without
`stem: "*.hisi"`.

```sh
PYTHONPATH=/path/to/platform/tools/extract-utils \
BLA_ORIGINAL_FILESYSTEMS=/path/to/original-filesystems \
BLA_EXTRACTED_VENDOR=/path/to/vendor/kirin970-common \
  python3 -B -m unittest discover -s tests -v
```
