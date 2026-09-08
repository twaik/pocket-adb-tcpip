# pocket-adb-tcpip

Android app that connects to another Android device over USB (OTG) and sends the adb
`tcpip:<port>` command directly - the same thing `adb tcpip 5555` does from a PC - so the target
starts listening for adb over TCP. No PC, no root, no wireless-debugging support needed on the
target.

## Why

Useful for old devices that have "USB debugging" but no "Wireless debugging" toggle: plug the
target into another phone via an OTG cable, tap a button here, then `adb connect
<target-ip>:<port>` works from anywhere that can reach it (e.g. over Tailscale).

## Requirements

- Host phone with USB OTG/host mode, Android 8.0+ (minSdk 26)
- Target device with "USB debugging" enabled in Developer options

## Build

```
./gradlew assembleDebug
```

APK: `build/app/outputs/apk/debug/app-debug.apk`

## Use

1. Connect the target device via an OTG cable.
2. Open the app, grant USB permission.
3. Tap "Enable adb over TCP/IP". First time, approve "Allow USB debugging?" on the target's
   screen and try again.
4. `adb connect <target-ip>:<port>`

## How it works

The app implements the adb wire protocol (framing, CNXN/AUTH handshake, RSA signing) directly
over USB bulk transfer - see [app/AdbProtocol.java](app/AdbProtocol.java). No AndroidX, no
third-party libraries.
