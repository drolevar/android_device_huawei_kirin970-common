# BLA .225 common extraction baseline

All 958 source paths were read from the BLA-L29 stock filesystems captured through TWRP on 2026-11-14. The source list pins their original SHA-1 bytes using extract-utils syntax; original filesystem images and files remain untouched in the private engineering workspace. This list replaces the unverified CLT source attribution without claiming runtime equivalence.

The measured super SHA-256 is `40700e7f8162cb3736817775c0eb6694ced405e2d25655165e513b535d521535`. Stock vendor fingerprint is `kirin970/kirin970/kirin970:10/QP1A.190711.020/root202205170102:user/test-keys`; vendor/default.prop declares VNDK 29. Public source contains no binary blobs.

The selected extract-utils parser no longer recognizes NO_ETC_XML. The two affected files are opaque encrypted/binary formats, not text XML: native_packages.xml SHA-256 d5cf131d132e2186d0a232c1114caa87d1eff92946ced51308570417ea87147d and observe_config_encryt.xml SHA-256 199a9c571a7ca75f1a94082657e93689d1f00023161eee9ea327b7c0fcc78850. MAKE_COPY_RULE_ONLY preserves their exact bytes without routing them through XML validation. This is file-specific, not a blanket build check bypass.

The inherited libSmartAE instruction fixup was previously an unchecked first-match replacement. It now requires the measured original SHA-256, ELF64/AArch64 identity, and exactly one instruction match before touching the extracted copy. The helper logs input/output hashes; subsequent native-library dependency fixups can change the final hash again. This mechanically constrains the donor change; camera runtime behavior remains untested. Other inherited native-library/RC fixups still require final extraction and dependency auditing against the resolved platform.

Run parser and guarded-fixup regressions with PYTHONPATH pointing to the selected tools/extract-utils and `python3 -B -m unittest discover -s tests -v`. Five tests passed, including unknown inputs and absent/ambiguous instruction matches. No device change or image validation is established.

SPDX-License-Identifier: Apache-2.0
