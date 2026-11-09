# Kirin 970 common tree: Blanc / LineageOS 24 preparation

The `blanc-lineage-24.0` development branch preserves the existing common tree
at `c6e08caaa721c82bc9b0723cc2aa203ca790ca9a`, imported from
[LineageOS Gerrit 495204](https://review.lineageos.org/c/LineageOS/android_device_huawei_kirin970-common/+/495204).
It is a source preparation baseline, not a claim of BLA-L29 EMUI 12 `.225`
runtime compatibility. Use the
[pinned Huawei manifest](https://github.com/drolevar/lineage_manifest/tree/blanc-lineage-24.0/huawei).

## Small, source-supported change

`common.mk` enables `$(call soong_config_set_bool,libui,legacy_gralloc,true)`.
Lineage 24's [libui Android.bp](https://github.com/LineageOS/android_frameworks_native/blob/lineage-24.0/libs/ui/Android.bp)
and [GraphicBufferMapper.cpp](https://github.com/LineageOS/android_frameworks_native/blob/lineage-24.0/libs/ui/GraphicBufferMapper.cpp)
explicitly permit the retained older mapper path with this switch. It matches this tree's
declared mapper 2.1/allocator 2.0 configuration. It does not repair ION policy,
ELF symbols, graphics firmware, or composer behavior by itself.

## Work still required for the selected platform

- Audit the legacy audio HIDL v5 framework support and the `libui-v29` /
  `libjsoncpp-v30` / extraction patches against Lineage 24. The earlier 22.2
  patches are references, not an automatically applicable patch stack.
- Validate FCM level 5, legacy VNDK dependencies, mixed-width vendor binaries,
  and each referenced package against the pinned source checkout. Do not set
  `ALLOW_MISSING_DEPENDENCIES` or disable compatibility checks to hide failures.
- Audit the kernel BPF backports against the actual Lineage 24 loader/programs.
  A kernel-version override cannot implement a missing helper, map type,
  verifier rule, or socket-lifetime fix.
- Check capabilities in the selected zygote path and the kernel's actual
  capability implementation. Changing `CAP_LAST_CAP` alone is not a backport.
- Determine encryption requirements from the exact vendor/keymaster and kernel
  ABI. A policy version and the kernel key-management API are separate concerns;
  do not assume every old device needs fscrypt v2 or silently remove encryption.
- Validate physical and logical partitions, especially the inherited
  `patch`-to-`/metadata` mapping, boot header offsets, ramdisk size, and fstab's
  formatting flags. These are donor settings, not current-device measurements.
- Audit shipping API and security-patch declarations against stock provenance.
  Their presence in this donor tree is not evidence of a BLA launch API or a
  newly patched vendor image.

The inline kernel remains the maintained `hisi-oss` descendant selected by the
manifest. `TARGET_KERNEL_CLANG_VERSION = r416183b` describes that development
tree; it must not be confused with the older toolchain expected by Huawei's
pristine BLA EMUI 10 source archive. The archive is a separate provenance and
comparison reference, not evidence that EMUI 12's shipped kernel is identical.

No kernel behavior, partition mapping, encryption, networking, graphics,
telephony, or official-device support is certified by these source changes.
