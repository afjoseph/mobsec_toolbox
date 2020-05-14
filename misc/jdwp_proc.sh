readonly JDWP_FORWARD_PORT=7777
PROC_NAME=$1

if ! adb shell ps | grep "$PROC_NAME"; then
    echo "app not running"
fi

PROC_PID=$(adb shell ps | grep "$PROC_NAME" | awk '{print $2}')
PROC_PKG_NAME=$(adb shell pm list packages | grep -i "$PROC_NAME" | awk -F "package:" '{print $2}')

echo "PID of target app: $PROC_PID"
echo "Package name of target app: $PROC_PKG_NAME"

echo "Killing app..."
adb shell kill "$PROC_PID"

echo "Set app as debuggable"
adb shell am set-debug-app -w --persistent "$PROC_PKG_NAME"

echo "Launching again..."
adb shell monkey -p "$PROC_PKG_NAME" 1


sleep 2

PROC_PID=$(adb shell ps | grep "$PROC_NAME" | awk '{print $2}')

echo "Attaching to app through JDWP on port $JDWP_FORWARD_PORT"
adb forward tcp:"$JDWP_FORWARD_PORT" jdwp:"$PROC_PID"

{ echo "suspend"; cat; } | jdb -attach localhost:"$JDWP_FORWARD_PORT"
