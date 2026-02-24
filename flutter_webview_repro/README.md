# Flutter WebView Repro App

This app is a minimal hybrid-style Flutter app to reproduce WebView page-load slowness on real devices.
It is intentionally aligned to your `kmart_webview_repro` pattern using `flutter_inappwebview`.

## What it gives you
- URL bar + in-app navigation (`Go`, `Back`, `Forward`, `Reload`)
- Optional request blocking toggle for tracker-heavy domains
- WebView cache/cookie clear action
- Native load signals (`onPageStarted`, progress, `onPageFinished`)
- Android WebView debugging enabled (`isInspectable: true`) for `chrome://inspect`

## Run
```bash
cd flutter_webview_repro
flutter pub get
flutter run --dart-define=START_URL=https://your-site.example.com
```

## Build installable APK
```bash
cd flutter_webview_repro
flutter build apk --debug --dart-define=START_URL=https://your-site.example.com
```

APK path:
- `build/app/outputs/flutter-apk/app-debug.apk`

## Chrome WebView inspect
1. Run the app in **debug** mode on Android device.
2. Enable USB debugging on device.
3. Connect device via USB.
4. Open desktop Chrome: `chrome://inspect/#devices`.
5. Inspect the app's WebView target.

## Notes
- This is a repro app, not a patch of your production APK.
- If your production app adds auth headers/tokens/cookies, reproduce those conditions here to get closer timing parity.
- Keep this app in **debug** build when using `chrome://inspect`.
