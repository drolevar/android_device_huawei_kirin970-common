# Unique filenames for the three stock security services

`MODULE=...service.hisi` previously changed only the generated module name;
extract-utils retained the unsuffixed installed stem. The stock and generic
modules therefore generated the same vendor/SYMBOLS output paths. The extraction
recipe now copies the three stock executables to their existing `.hisi` module
names and copies their rc files to matching `.hisi.rc` destinations.

`fixups/hisi_services.py` requires the exact measured stock SHA-256, exactly one
original path as a service executable token, and the pinned output SHA-1/SHA-256.
It changes only that executable token. Service IDs, classes, users, groups,
interface declarations and all other rc bytes are unchanged. All three ELF
payloads remain byte-identical to their original BLA inputs; existing ELF input
pins and strict generated dependency/ELF checks are retained. No VINTF source,
HAL implementation, or generic secure-element implementation is substituted.

The selected extract-utils supports `OVERRIDES` in its parser but emits it only
for APK packages, not `cc_prebuilt_binary`. No ineffective override flag is added.
The generated vendor product still selects the same three `.hisi` modules. This
fix makes their filesystem destinations disjoint from generic build outputs.

## SELinux labels

`BoardConfigCommon.mk` already includes
`hardware/huawei/sepolicy/hisi/SEPolicy.mk`. The existing hardware vendor
`file_contexts` already labels the renamed secure-element path as
`hal_secure_element_default_exec`. Two precise rules in the new common vendor
policy directory give gatekeeper/keymaster their original
`hal_gatekeeper_default_exec` / `hal_keymaster_default_exec` types.
The patterns contain single regex escapes and match the literal new filenames.
No domains, allow rules, permissive settings, or policy-check exceptions are added.

## Verification (2026-11-14)

Before replay, the existing generated common (541 MiB) and blanc (129 MiB) vendor
trees were copied to ignored cache storage. Full common extraction then ran from
the original filesystems into a separate ignored staging directory using the
selected extract-utils. Live source/vendor inputs were not changed during the
parent build. The three live executables/rc inputs still match the backup.

Thirteen owning-project tests passed with the measured source and staging output,
including missing/ambiguous/non-service path rejection, changed-input rejection,
the actual extractor's module/stem behavior, all three original/new SELinux type
matches, measured rc hash replay, generated copy destinations, and unchanged ELF
bytes. [service-names-20261114.json](service-names-20261114.json) records hashes and
metadata without proprietary payloads.

```sh
PYTHONPATH=/path/to/platform/tools/extract-utils \
BLA_ORIGINAL_FILESYSTEMS=/path/to/original-filesystems \
BLA_EXTRACTED_VENDOR=/path/to/staged/kirin970-common \
  python3 -B -m unittest discover -s tests -v
```

Without the two BLA variables, the private-input replay tests are skipped. Main
must publish/select the source, regenerate the live vendor tree after the active
build ends, and retry the actual graph/packaging build. This does not claim a
completed target build, policy compilation, or service/runtime validation.
