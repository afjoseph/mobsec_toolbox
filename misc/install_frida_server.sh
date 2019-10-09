#!/bin/bash

# >> START BASH UTIL
# ============================================================
# ============================================================
# Enable function error propagation
set -o errtrace
set -o pipefail
set -u

trap 'EXIT=$?; log_error " ERR in LINE: $LINENO"; exit $EXIT' ERR
readonly LOG_TAG="$(basename "$0")"
readonly ERROR_COLOR=$(tput setaf 1)
readonly INFO_COLOR=$(tput setaf 6)
readonly RESET_COLOR=$(tput sgr0)
readonly EXIT_FAIL=1
readonly EXIT_SUCCESS=0

log_info() {
    echo  "${INFO_COLOR}[+] [${LOG_TAG}] ${1}${RESET_COLOR}"
}

log_error() {
    echo "${ERROR_COLOR}[!] [${LOG_TAG}] ${1}${RESET_COLOR}"
}
# << END BASH UTIL
# ============================================================
# ============================================================

main() {
    local local_server=""

    # TODO: Use a local_server
    for i in "$@"; do
        case $i in 
            -use_local_server=*)
                local_server="${i#*=}"
        esac
    done

    # Check that only one device is attached since we're not specifying any serial numbers in ADB commands
    # 3 = 1 device + 2 default lines from `adb devices` output
    if (( $(adb devices | wc -l) != 3)); then
        echo "[!] Only one attached ADB device allowed"
    fi

    if adb root | grep "cannot run"; then
        echo "[!] Device is not rooted"
        exit 2
    fi

    readonly FRIDA_VERSION=$(frida --version)
    ARCH=$(adb shell getprop ro.product.cpu.abi)

    echo "[+] Found a connected device with arch: $ARCH"

    if [ "$ARCH" = "arm64-v8a" ]; then
        ARCH="arm64"
    fi

    echo "[+] Fetching frida server from GitHub releases page..."
    wget -q -O - https://api.github.com/repos/frida/frida/releases \
        | jq -c ".[0].assets | .[] | select(.name | contains(\"frida-server-$FRIDA_VERSION-android-$ARCH.xz\"))" \
        | jq '.browser_download_url' \
        | tr -d '"' \
        | xargs wget -q --show-progress

    FRIDA_SERVER_OUT_NAME=$(find . -type f -name "*xz")

    if [ ! -f "$FRIDA_SERVER_OUT_NAME" ] || ! file "$FRIDA_SERVER_OUT_NAME" | grep -qe "XZ compressed.*$"; then
        echo "[!] Server failed to download"
        exit 2
    fi

    xz -d "$FRIDA_SERVER_OUT_NAME"
    # xz removes extension so we should remove it too
    FRIDA_SERVER_OUT_NAME="${FRIDA_SERVER_OUT_NAME%.*}"

    if [ ! -f "$FRIDA_SERVER_OUT_NAME" ] || ! file --mime-encoding "$FRIDA_SERVER_OUT_NAME" | grep -q "binary"; then
        echo "[!] Downloaded file is not a proper binary"
        exit 2
    fi

    echo "[+] Binary downloaded. Pushing to /data/local/tmp"
    adb push "$FRIDA_SERVER_OUT_NAME" /data/local/tmp
    adb shell "chmod u+x /data/local/tmp/$FRIDA_SERVER_OUT_NAME"

    # Cleaning up
    find . -type f -name "*xz" -delete
    rm -rf "$FRIDA_SERVER_OUT_NAME"

    echo "[+] Running server. Feel free to quit this script"
    adb shell "/data/local/tmp/$FRIDA_SERVER_OUT_NAME -D"
}

main "$@"
