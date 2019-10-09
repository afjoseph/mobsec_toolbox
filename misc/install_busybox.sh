#!/bin/bash

trap 'echo Failed at line: $LINENO' ERR

echo "[+] > Busybox installer"
ARCH=$(adb shell "uname -m")
if echo "$ARCH" | grep i686 1>/dev/null; then
    echo "[+] i686 arch detected."
    curl "https://busybox.net/downloads/binaries/1.28.1-defconfig-multiarch/busybox-i486" > /tmp/busybox 
elif echo "$ARCH" | grep "arm" 1>/dev/null; then # TODO: Check for armv8
    echo "[+] arm arch detected."
    curl "https://busybox.net/downloads/binaries/1.28.1-defconfig-multiarch/busybox-armv7r" > /tmp/busybox 
fi

echo "[+] Pushing busybox to device"
adb push /tmp/busybox /data/data/busybox 1>/dev/null


echo "[+] Attempting root"
adb root 1> /dev/null
if adb remount | grep -v "succeeded" 1>/dev/null; then
    echo "[!] Remount failed."
    exit 2
fi

echo "[+] Installing"
adb shell "mv /data/data/busybox /system/bin/busybox && chmod 755 /system/bin/busybox && /system/bin/busybox --install /system/bin"

if adb shell "busybox" | grep "not found"; then
    echo "[!] Busybox failed to install"
fi

echo "[+] Done"
