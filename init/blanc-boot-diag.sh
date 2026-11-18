#!/system/bin/sh
# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
# Bounded unencrypted /metadata/boot_diag capture for userdebug/eng bring-up.

BASE="/metadata/boot_diag"
CUR="$BASE/cur"
PREV="$BASE/prev"

mkdir -p "$BASE"
chmod 0700 "$BASE"

rm -rf "$PREV"
if [ -d "$CUR" ]; then
    mv "$CUR" "$PREV"
fi
mkdir -p "$CUR/tombstones"
chmod 0700 "$CUR" "$CUR/tombstones"

logcat_pid=""
tb_copied=0
boot_done=0
i=0

while [ "$i" -lt 90 ]; do
    if [ -z "$logcat_pid" ] && [ -e /dev/socket/logdr ]; then
        /system/bin/logcat -b all -v threadtime -f "$CUR/logcat.txt" -r 1024 -n 3 </dev/null >/dev/null 2>&1 &
        logcat_pid=$!
    fi

    dmesg > "$CUR/dmesg.txt.tmp" 2>/dev/null && mv -f "$CUR/dmesg.txt.tmp" "$CUR/dmesg.txt"
    getprop > "$CUR/getprop.txt.tmp" 2>/dev/null && mv -f "$CUR/getprop.txt.tmp" "$CUR/getprop.txt"
    ls -la /sys/fs/bpf /sys/fs/bpf/netd_shared /sys/fs/bpf/tethering > "$CUR/bpf.txt.tmp" 2>&1
    mv -f "$CUR/bpf.txt.tmp" "$CUR/bpf.txt"

    if [ "$tb_copied" -lt 8 ]; then
        for f in /data/tombstones/tombstone_*; do
            [ -e "$f" ] || break
            case "$f" in
                *.pb) continue ;;
            esac
            name="${f##*/}"
            if [ ! -e "$CUR/tombstones/$name" ]; then
                dd if="$f" of="$CUR/tombstones/$name.tmp" bs=4096 count=64 2>/dev/null && mv -f "$CUR/tombstones/$name.tmp" "$CUR/tombstones/$name"
                tb_copied=$((tb_copied + 1))
                [ "$tb_copied" -ge 8 ] && break
            fi
        done
    fi

    sync
    [ "$boot_done" -eq 1 ] && break

    if [ "$(getprop sys.boot_completed)" = "1" ]; then
        boot_done=1
    fi

    i=$((i + 1))
    sleep 2
done

if [ -n "$logcat_pid" ]; then
    kill "$logcat_pid" 2>/dev/null || true
fi
sync
