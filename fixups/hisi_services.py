# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
"""Rename only the executable token in three exactly pinned BLA stock rc files."""

import hashlib
from pathlib import Path
import re


SERVICE_RCS = {}
for service, version, label, input_sha1, input_sha256, output_sha1, output_sha256 in (
    ("gatekeeper", "1.0", "hal_gatekeeper_default_exec",
     "14787a28eab3435381646dde6e92e6d286a69fe2",
     "ac31b40c9feabca1c449a5b39ff8e1427fa88c9c911f6a4f96f8674b656d9e40",
     "0340c2f27e9e12a87ebc904848809448767b5497",
     "258278f5624f3c8f9ea527a92e10926d4fcc6ce4774802d2317708bcec1cdd91"),
    ("keymaster", "3.0", "hal_keymaster_default_exec",
     "f31babff3abdd73a905fb071671fde5c818d6a11",
     "101a172606c97540b1226efbc9af55e989e6309456139ce439d73f94fcacf3ce",
     "4c653e22a73fb134c17784a11384d13d30a72f98",
     "931c7f28b319a03d3d49cf1e3b3bbc9e77b021dcdd1c01a8086197698657ceea"),
    ("secure_element", "1.0", "hal_secure_element_default_exec",
     "1aefadf42180a9939378c3a8bba63f9b28b749e7",
     "03c966c813bc8df11d1084d8aef6498529fc153726a6fbddbd6c90e10b7e894a",
     "aa564c83a08c13766c5244d362a2d176ededa257",
     "e2fd97212bfe3e387d0b89f5b262ae55b16e2c3c6974ec8d48fb9e97f983548d"),
):
    stem = f"android.hardware.{service}@{version}-service"
    SERVICE_RCS[f"vendor/etc/init/{stem}.hisi.rc"] = {
        "old_exec": f"/vendor/bin/hw/{stem}",
        "new_exec": f"/vendor/bin/hw/{stem}.hisi",
        "exec_context": f"u:object_r:{label}:s0",
        "input_sha1": input_sha1, "input_sha256": input_sha256,
        "output_sha1": output_sha1, "output_sha256": output_sha256,
    }


def rewrite_exec_path(data, old, new):
    if data.count(old) != 1:
        raise ValueError("rc must contain exactly one original executable path")
    pattern = rb"(?m)^service[ \t]+[^ \t\r\n]+[ \t]+" + re.escape(old) + rb"(?=[ \t\r\n]|$)"
    if len(re.findall(pattern, data)) != 1:
        raise ValueError("original path must be the exact executable token of one service")
    return data.replace(old, new, 1)


def patch_rc(data, destination):
    if destination not in SERVICE_RCS:
        raise ValueError("Unrecognized BLA service rc destination")
    record = SERVICE_RCS[destination]
    if hashlib.sha256(data).hexdigest() != record["input_sha256"]:
        raise ValueError("BLA service rc input SHA-256 mismatch; review the new stock input")
    output = rewrite_exec_path(data, record["old_exec"].encode(), record["new_exec"].encode())
    if (hashlib.sha256(output).hexdigest() != record["output_sha256"]
            or hashlib.sha1(output).hexdigest() != record["output_sha1"]):
        raise ValueError("BLA service rc output hash mismatch")
    return output


def blob_fixup(ctx, file, file_path, *args, **kwargs):
    destination = Path(file_path)
    output = patch_rc(destination.read_bytes(), file.dst)
    destination.write_bytes(output)
