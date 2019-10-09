#!/bin/bash

echo "Old GPS ADID: $(adb shell cat /data/data/com.google.android.gms/shared_prefs/adid_settings.xml)"
adb shell rm -f /data/data/com.google.android.gms/shared_prefs/adid_settings.xml
