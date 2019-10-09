#!/bin/bash

trap 'echo Failed at line: $LINENO' ERR

SYSTEM_CACERT_PATH="/system/etc/security/cacerts/"

usage() {
	echo "$0 [pem_cert]"
    echo "  Description: "
    echo "  Install CA certificates at system-level"
    echo "  example: ./install_sys_cert.sh ~/.mitmproxy/mitmproxy-ca-cert.cer"
}

main() {
    local pem_cert
    local cert_name
    local cert_name_path

    if [ "$#" -ne 1 ]; then
        usage
        exit 2
    fi

    pem_cert=$1

    if [ ! -f "$pem_cert" ]; then
        echo "File doesn't exist"
        exit 2
    fi

    if ! file "$pem_cert" | grep -q "PEM certificate" ; then
        echo "Not a PEM certificate"
        exit 2
    fi

    cert_name=$(openssl x509 -inform PEM -subject_hash_old -in "$pem_cert" | head -1).0
    cert_name_path="/tmp/$cert_name"

    echo "[+] Cert name: $cert_name"
    cp "$pem_cert" "$cert_name_path"

    echo "[+] Attempting root"
    adb root 1>/dev/null

    if adb remount | grep -v "succeeded" 1>/dev/null; then
        echo "[!] Remount failed."
        exit 2
    fi

    echo "[+] Pushing to device's system certificates path [$SYSTEM_CACERT_PATH]"
    adb push "$cert_name_path" "$SYSTEM_CACERT_PATH" 1>/dev/null

    echo "[+] Rebooting..."
    adb reboot

    echo "Waiting for device..."
    adb wait-for-device
    
    if adb shell "ls $SYSTEM_CACERT_PATH" | grep "$cert_name" 1>/dev/null; then 
        echo "Certificate installed successfully"
    else
        echo "Failed to install system certificate"
        exit 2
    fi

    echo "[+] Done"
    echo '[+] Run "adb shell settings put global http_proxy IP:PORT" to configure proxy'
    echo "[+] Something like this would work for GM:"
    printf "\tadb shell settings put global http_proxy 10.0.3.2:3223\n"

    rm -rf "${cert_name:?}"
}

main "$@"
