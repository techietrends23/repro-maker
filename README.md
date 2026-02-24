# repro-creator

`repro_creator.py` builds a safe, debuggable repro harness from an APK.

It does not modify the original app. It extracts likely web URLs from APK contents, then generates a standalone Android WebView app with:
- `WebView.setWebContentsDebuggingEnabled(true)` for `chrome://inspect`
- native lifecycle timings (`onPageStarted`, `onPageCommitVisible`, `onPageFinished`)
- JS Navigation/Resource timing capture (`performance.getEntriesByType(...)`)

## Requirements
- Python 3.9+
- Android Studio (to build/run generated harness)
- Optional: `aapt` or `apkanalyzer` for package-name extraction

## Usage
```bash
python3 repro_creator.py \
  --apk /path/to/app.apk \
  --out ./out/repro
```

Optional flags:
```bash
--max-targets 30
--extra-url https://your-primary-web-entry.example.com
--package-id com.yourorg.repro
--app-name "My WebView Repro"
```

## Output
- `out/repro/analysis/report.json`
- `out/repro/analysis/report.md`
- `out/repro/webview-repro-harness/` (Android project)

## Run and debug
1. Open `webview-repro-harness` in Android Studio.
2. Run the debug app on a device/emulator.
3. In Chrome desktop: `chrome://inspect/#devices`.
4. Inspect the WebView and compare Network + Performance traces against web baseline.

## Notes
- If the APK is obfuscated/encrypted, URL extraction may be partial.
- Add known URLs with `--extra-url` to force inclusion.
