# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
"""Route IRadio@1.4 getVoiceRegistrationStateResponse to V1_2 when available."""

import hashlib
from pathlib import Path

EXPECTED_SHA256_64 = "adb0746790f70a5d8e37eec0df40e7c73eec689733281b325579869cbcf16195"
EXPECTED_OUTPUT_SHA256_64 = "70bc52c75ae5dcb36cd964397c39fa1709fff6203e681a5274c89a098c84795e"
OFFSET_64 = 0x752C8
WINDOW_64_OLD = bytes.fromhex("e8 7a 7b f8 09 29 40 f9 e9 03 00 b4 62 fe ff d0 e3 fe ff 90")
# At 0x752d0: replace `cbz x9, 0x7534c` (e9 03 00 b4) with `b 0x7534c` (1f 00 00 14).
WINDOW_64_NEW = bytes.fromhex("e8 7a 7b f8 09 29 40 f9 1f 00 00 14 62 fe ff d0 e3 fe ff 90")

EXPECTED_SHA256_32 = "b64dc29edea802a95fdf93652248ed4c9b62b11f367ca17a75bdae953f76476a"
EXPECTED_OUTPUT_SHA256_32 = "9081bd1cf5618ea01f5f2e0c5ac1194c97b9b611fe64a8f2f24e0208a83161e6"
OFFSET_32 = 0x4B570
WINDOW_32_OLD = bytes.fromhex("0b 9f 56 f8 27 00 81 6a 71 b3 00 95 8f 4a 90 4b")
# At 0x4b578: replace Thumb-2 `cbz r1, 0x4b5d8` (71 b3) with `b 0x4b5d8` (2e e0).
WINDOW_32_NEW = bytes.fromhex("0b 9f 56 f8 27 00 81 6a 2e e0 00 95 8f 4a 90 4b")


def _patch_window(
    data: bytes, offset: int, old_win: bytes, new_win: bytes, label: str
) -> bytes:
    if len(old_win) != len(new_win):
        raise ValueError(f"{label} window length mismatch")
    if data.count(old_win) != 1:
        raise ValueError(f"{label} requires exactly one instruction window match")
    if data[offset : offset + len(old_win)] != old_win:
        raise ValueError(f"{label} instruction window not at expected offset {hex(offset)}")
    return data[:offset] + new_win + data[offset + len(old_win) :]


def patch_libril_voicereg(data: bytes) -> bytes:
    """Patch libril.so so IRadio@1.4 uses getVoiceRegistrationStateResponse_1_2."""
    digest = hashlib.sha256(data).hexdigest()
    if digest in (EXPECTED_OUTPUT_SHA256_64, EXPECTED_OUTPUT_SHA256_32):
        return data
    if digest == EXPECTED_SHA256_64:
        if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or data[18:20] != b"\xb7\x00":
            raise ValueError("64-bit libril.so must be little-endian AArch64 ELF64")
        return _patch_window(data, OFFSET_64, WINDOW_64_OLD, WINDOW_64_NEW, "libril64")
    if digest == EXPECTED_SHA256_32:
        if len(data) < 52 or data[:6] != b"\x7fELF\x01\x01" or data[18:20] != b"\x28\x00":
            raise ValueError("32-bit libril.so must be little-endian ARM ELF32")
        return _patch_window(data, OFFSET_32, WINDOW_32_OLD, WINDOW_32_NEW, "libril32")
    raise ValueError(f"BLA libril.so input SHA-256 mismatch ({digest}); review the new blob")


def blob_fixup(ctx, file, file_path, *args, **kwargs):
    destination = Path(file_path)
    original = destination.read_bytes()
    orig_sha = hashlib.sha256(original).hexdigest()
    patched = patch_libril_voicereg(original)
    destination.write_bytes(patched)
    print(
        "BLA libril VoiceRegistrationState V1_2 fixup SHA-256: "
        + orig_sha
        + " -> "
        + hashlib.sha256(patched).hexdigest()
    )
