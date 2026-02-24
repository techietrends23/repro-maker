# repro-creator

`repro_creator.py` builds a safe, debuggable repro harness from an APK.

It does not modify the original app. It extracts likely web URLs from APK contents, then generates a standalone Android WebView app with:
- `WebView.setWebContentsDebuggingEnabled(true)` for `chrome://inspect`
- native lifecycle timings (`onPageStarted`, `onPageCommitVisible`, `onPageFinished`)
- JS Navigation/Resource timing capture (`performance.getEntriesByType(...)`)
- URL entry + navigation controls (Go, Back, Forward, Reload, Clear)

## Requirements
- Python 3.9+
- Android Studio (to build/run generated harness)
- Java 17+ (required when using `--build-apk`)
- Optional: `aapt` or `apkanalyzer` for package-name extraction

## Usage
```bash
python3 repro_creator.py \
  --apk /path/to/app.apk \
  --out ./out/repro
```

From an app already installed on device:
```bash
python3 repro_creator.py \
  --device-package com.your.app \
  --out ./out/repro \
  --adb-serial YOUR_DEVICE_SERIAL
```

Interactive package picker from connected device:
```bash
python3 repro_creator.py \
  --interactive-device-select \
  --out ./out/repro \
  --adb-serial YOUR_DEVICE_SERIAL
```

Optional flags:
```bash
--max-targets 30
--extra-url https://your-primary-web-entry.example.com
--package-id com.yourorg.repro
--app-name "My WebView Repro"
--build-apk
--install-via-adb --adb-serial YOUR_DEVICE_SERIAL
```

## Output
- `out/repro/analysis/report.json`
- `out/repro/analysis/report.md`
- `out/repro/webview-repro-harness/` (Android project)
- `out/repro/repro-harness-debug.apk` (when `--build-apk` is used)

## Run and debug
1. Open `webview-repro-harness` in Android Studio.
2. Run the debug app on a device/emulator.
3. In Chrome desktop: `chrome://inspect/#devices`.
4. Inspect the WebView and compare Network + Performance traces against web baseline.

## Notes
- The original protected APK cannot be recreated exactly (different binary/signing keys).
- `--build-apk` auto-downloads Gradle if it is not installed locally.
- `--device-package` pulls the installed APK splits from device via `adb` and uses `base.apk` for analysis.
- `--interactive-device-select` lists installed third-party packages (`pm list packages -3`) and prompts for a numeric selection.
- If the APK is obfuscated/encrypted, URL extraction may be partial.
- Add known URLs with `--extra-url` to force inclusion.
