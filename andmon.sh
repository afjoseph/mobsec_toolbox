#!/bin/bash

is_first_pull=true

if [ -f timestamp ]; then
    is_first_pull=false
fi

if [ $is_first_pull = true ]; then
    echo "[+] Attempting root"
    adb root 1>/dev/null

    echo "[+] Taking 1st shot"
    adb shell "touch /sdcard/timestamp"
    adb pull "/sdcard/timestamp" 1>/dev/null

    echo "[+] Done. Analyze and run again to calculate file delta"
else
    echo "[+] Taking 2nd shot"
    adb shell "find / \( -type f -a -newer /sdcard/timestamp \) -o -type d \( -path /dev -o -path /proc -o -path /acct -o -path /sys \) -prune | grep -v -e \"^/dev$\" -e \"^/proc$\" -e \"^/sys$\"" | tee diff.mon

    chmod 600 diff.mon

    echo "[+] Done. Diff saved in diff.mon"
fi
