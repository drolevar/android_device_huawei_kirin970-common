# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
"""Constrain the inherited SmartAE instruction fixup to the measured BLA blob."""

import hashlib
from pathlib import Path

EXPECTED_SHA256 = "8dbbd19606ae3cb5d893ffecfaba1e76baa8b519bcd16ec95a4783324477a9e3"
PATTERN = bytes.fromhex("9F 02 0A B9")
REPLACEMENT = bytes.fromhex("1F 20 03 D5")


def patch_smartae(data):
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        raise ValueError("BLA SmartAE input SHA-256 mismatch; review the new blob")
    if data[:6] != b"\x7fELF\x02\x01" or data[18:20] != b"\xb7\x00":
        raise ValueError("BLA SmartAE must be little-endian AArch64 ELF64")
    if data.count(PATTERN) != 1:
        raise ValueError("BLA SmartAE requires exactly one instruction match")
    return data.replace(PATTERN, REPLACEMENT, 1)


def blob_fixup(ctx, file, file_path, *args, **kwargs):
    destination = Path(file_path)
    original = destination.read_bytes()
    patched = patch_smartae(original)
    destination.write_bytes(patched)
    print("BLA SmartAE instruction fixup SHA-256: " + EXPECTED_SHA256 + " -> "
          + hashlib.sha256(patched).hexdigest())
