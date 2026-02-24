#!/usr/bin/env python3
"""Create a debuggable WebView repro harness from an APK.

This tool does not modify the source APK. It extracts likely web URLs and
builds a standalone Android project for reproducible WebView measurements.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import textwrap
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

URL_PATTERN = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{4,}")
DEFAULT_PACKAGE_ID = "com.reprocreator.harness"
DEFAULT_APP_NAME = "WebView Repro Harness"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def clean_url(raw: bytes) -> str | None:
    url = raw.decode("utf-8", errors="ignore").strip().rstrip("'\"),;]>}\\")
    if not url:
        return None

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    lowered = url.lower()
    if "schemas.android.com" in lowered or "www.w3.org" in lowered:
        return None

    return url


def try_extract_package_name(apk_path: Path) -> str | None:
    commands = [
        ["aapt", "dump", "badging", str(apk_path)],
        ["apkanalyzer", "manifest", "application-id", str(apk_path)],
    ]

    for cmd in commands:
        if shutil.which(cmd[0]) is None:
            continue
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.SubprocessError:
            continue

        stdout = completed.stdout.strip()
        if not stdout:
            continue

        if cmd[0] == "aapt":
            for line in stdout.splitlines():
                if line.startswith("package: name='"):
                    return line.split("'", 2)[1]
        else:
            return stdout.splitlines()[0].strip()

    return None


def scan_apk_for_urls(apk_path: Path, max_member_size_mb: int) -> dict[str, Any]:
    max_member_size = max_member_size_mb * 1024 * 1024
    hits: Counter[str] = Counter()
    locations: dict[str, list[str]] = defaultdict(list)
    scanned_members = 0
    skipped_members = 0

    with zipfile.ZipFile(apk_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir() or info.file_size <= 0:
                continue
            if info.file_size > max_member_size:
                skipped_members += 1
                continue

            scanned_members += 1
            try:
                blob = zf.read(info.filename)
            except Exception:
                skipped_members += 1
                continue

            for match in URL_PATTERN.finditer(blob):
                url = clean_url(match.group(0))
                if not url:
                    continue
                hits[url] += 1
                if len(locations[url]) < 3:
                    locations[url].append(info.filename)

    return {
        "hits": hits,
        "locations": locations,
        "scanned_members": scanned_members,
        "skipped_members": skipped_members,
    }


def choose_targets(url_hits: Counter[str], max_targets: int) -> list[str]:
    scored: list[tuple[int, int, str]] = []
    for url, hit_count in url_hits.items():
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue

        score = hit_count
        if parsed.path in {"", "/"}:
            score += 2
        if any(token in parsed.path.lower() for token in ["index", "home", "login", "app"]):
            score += 1
        scored.append((score, hit_count, url))

    scored.sort(key=lambda item: (item[0], item[1], -len(item[2])), reverse=True)

    selected: list[str] = []
    seen = set()
    for _, _, url in scored:
        if url in seen:
            continue
        selected.append(url)
        seen.add(url)
        if len(selected) >= max_targets:
            break

    return selected


def summarize_domains(url_hits: Counter[str], limit: int) -> list[dict[str, Any]]:
    domain_hits: Counter[str] = Counter()
    for url, hit_count in url_hits.items():
        netloc = urlparse(url).netloc
        if netloc:
            domain_hits[netloc] += hit_count

    return [
        {"domain": domain, "hits": hits}
        for domain, hits in domain_hits.most_common(limit)
    ]


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, content: str) -> None:
    ensure_parent(path)
    path.write_text(content, encoding="utf-8")


def main_activity_template(package_id: str) -> str:
    template = textwrap.dedent(
        '''\
        package __PACKAGE_ID__

        import android.annotation.SuppressLint
        import android.graphics.Bitmap
        import android.os.Bundle
        import android.os.SystemClock
        import android.util.Log
        import android.webkit.ConsoleMessage
        import android.webkit.CookieManager
        import android.webkit.JavascriptInterface
        import android.webkit.WebChromeClient
        import android.webkit.WebResourceError
        import android.webkit.WebResourceRequest
        import android.webkit.WebResourceResponse
        import android.webkit.WebSettings
        import android.webkit.WebView
        import android.webkit.WebViewClient
        import android.widget.ArrayAdapter
        import androidx.appcompat.app.AppCompatActivity
        import __PACKAGE_ID__.databinding.ActivityMainBinding
        import org.json.JSONArray
        import org.json.JSONObject
        import java.text.SimpleDateFormat
        import java.util.Date
        import java.util.Locale

        class MainActivity : AppCompatActivity() {

            private lateinit var binding: ActivityMainBinding
            private val targets = mutableListOf<String>()

            private var pageStartMs: Long? = null
            private var commitVisibleMs: Long? = null
            private var pageFinishedMs: Long? = null

            override fun onCreate(savedInstanceState: Bundle?) {
                super.onCreate(savedInstanceState)
                binding = ActivityMainBinding.inflate(layoutInflater)
                setContentView(binding.root)

                WebView.setWebContentsDebuggingEnabled(true)
                configureWebView()
                configureButtons()
                loadTargets()

                if (targets.isNotEmpty()) {
                    loadUrl(targets.first())
                }
            }

            @SuppressLint("SetJavaScriptEnabled")
            private fun configureWebView() {
                val settings = binding.webView.settings
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                settings.databaseEnabled = true
                settings.loadsImagesAutomatically = true
                settings.allowFileAccess = false
                settings.mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
                settings.userAgentString = settings.userAgentString + " ReproHarness/1.0"

                binding.webView.addJavascriptInterface(ReproBridge(), "ReproBridge")

                binding.webView.webChromeClient = object : WebChromeClient() {
                    override fun onConsoleMessage(consoleMessage: ConsoleMessage): Boolean {
                        logLine(
                            "CONSOLE " +
                                consoleMessage.messageLevel() +
                                " " +
                                consoleMessage.message()
                        )
                        return super.onConsoleMessage(consoleMessage)
                    }
                }

                binding.webView.webViewClient = object : WebViewClient() {
                    override fun shouldOverrideUrlLoading(
                        view: WebView?,
                        request: WebResourceRequest?
                    ): Boolean {
                        return false
                    }

                    override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
                        super.onPageStarted(view, url, favicon)
                        pageStartMs = SystemClock.elapsedRealtime()
                        commitVisibleMs = null
                        pageFinishedMs = null
                        logLine("onPageStarted " + url)
                        updateSummary()
                    }

                    override fun onPageCommitVisible(view: WebView, url: String) {
                        super.onPageCommitVisible(view, url)
                        commitVisibleMs = SystemClock.elapsedRealtime()
                        logLine("onPageCommitVisible " + url)
                        updateSummary()
                    }

                    override fun onPageFinished(view: WebView, url: String) {
                        super.onPageFinished(view, url)
                        pageFinishedMs = SystemClock.elapsedRealtime()
                        logLine("onPageFinished " + url)
                        updateSummary()
                        collectWebPerf()
                    }

                    override fun onReceivedError(
                        view: WebView,
                        request: WebResourceRequest,
                        error: WebResourceError
                    ) {
                        super.onReceivedError(view, request, error)
                        if (request.isForMainFrame) {
                            logLine(
                                "ERROR main-frame code=" +
                                    error.errorCode +
                                    " desc=" +
                                    error.description
                            )
                        }
                    }

                    override fun onReceivedHttpError(
                        view: WebView,
                        request: WebResourceRequest,
                        errorResponse: WebResourceResponse
                    ) {
                        super.onReceivedHttpError(view, request, errorResponse)
                        if (request.isForMainFrame) {
                            logLine("HTTP main-frame status=" + errorResponse.statusCode)
                        }
                    }
                }
            }

            private fun configureButtons() {
                binding.btnLoad.setOnClickListener {
                    if (targets.isEmpty()) {
                        logLine("No URL targets found")
                        return@setOnClickListener
                    }
                    val index = binding.urlSpinner.selectedItemPosition.coerceIn(0, targets.lastIndex)
                    loadUrl(targets[index])
                }

                binding.btnClear.setOnClickListener {
                    CookieManager.getInstance().removeAllCookies(null)
                    CookieManager.getInstance().flush()
                    binding.webView.clearCache(true)
                    binding.webView.clearHistory()
                    logLine("Cache and cookies cleared")
                }
            }

            private fun loadTargets() {
                val text = assets.open("targets.json").bufferedReader().use { it.readText() }
                val payload = JSONObject(text)
                val arr: JSONArray = payload.optJSONArray("targets") ?: JSONArray()

                for (i in 0 until arr.length()) {
                    val url = arr.optString(i)
                    if (url.startsWith("http://") || url.startsWith("https://")) {
                        targets.add(url)
                    }
                }

                if (targets.isEmpty()) {
                    targets.add("https://example.com")
                }

                val adapter = ArrayAdapter(
                    this,
                    android.R.layout.simple_spinner_dropdown_item,
                    targets
                )
                binding.urlSpinner.adapter = adapter

                val sourceApk = payload.optString("sourceApkName", "unknown")
                binding.tvSummary.text = "Source: " + sourceApk + " | Targets: " + targets.size
            }

            private fun loadUrl(url: String) {
                logLine("Loading " + url)
                binding.webView.loadUrl(url)
            }

            private fun updateSummary() {
                val start = pageStartMs
                if (start == null) {
                    binding.tvSummary.text = "No page loaded yet"
                    return
                }

                val now = SystemClock.elapsedRealtime()
                val elapsed = now - start
                val commit = commitVisibleMs?.minus(start)
                val finish = pageFinishedMs?.minus(start)

                val sb = StringBuilder()
                sb.append("Native timing | elapsed=").append(elapsed).append("ms")
                if (commit != null) {
                    sb.append(" | commit=").append(commit).append("ms")
                }
                if (finish != null) {
                    sb.append(" | finish=").append(finish).append("ms")
                }
                binding.tvSummary.text = sb.toString()
            }

            private fun collectWebPerf() {
                val script = """
                    (function() {
                      try {
                        var nav = performance.getEntriesByType('navigation')[0] || null;
                        var resources = performance.getEntriesByType('resource') || [];
                        var slow = resources
                          .filter(function(r) { return r.duration > 1000; })
                          .sort(function(a, b) { return b.duration - a.duration; })
                          .slice(0, 20)
                          .map(function(r) {
                            return {
                              name: r.name,
                              type: r.initiatorType,
                              duration: Math.round(r.duration),
                              transferSize: r.transferSize || 0
                            };
                          });

                        var payload = {
                          kind: 'perf',
                          navigation: nav ? {
                            dns: Math.round(nav.domainLookupEnd - nav.domainLookupStart),
                            tcp: Math.round(nav.connectEnd - nav.connectStart),
                            tls: nav.secureConnectionStart > 0 ? Math.round(nav.connectEnd - nav.secureConnectionStart) : 0,
                            ttfb: Math.round(nav.responseStart - nav.requestStart),
                            domContentLoaded: Math.round(nav.domContentLoadedEventEnd),
                            loadEventEnd: Math.round(nav.loadEventEnd),
                            transferSize: nav.transferSize || 0,
                            encodedBodySize: nav.encodedBodySize || 0,
                            decodedBodySize: nav.decodedBodySize || 0
                          } : null,
                          resourceCount: resources.length,
                          topSlow: slow
                        };

                        window.ReproBridge.postMessage(JSON.stringify(payload));
                      } catch (e) {
                        window.ReproBridge.postMessage(JSON.stringify({ kind: 'error', message: String(e) }));
                      }
                    })();
                """.trimIndent()

                binding.webView.evaluateJavascript(script, null)
            }

            private fun handleJsPayload(payloadJson: String) {
                try {
                    val payload = JSONObject(payloadJson)
                    when (payload.optString("kind")) {
                        "perf" -> {
                            val nav = payload.optJSONObject("navigation")
                            if (nav != null) {
                                logLine(
                                    "NAV dns=" + nav.optInt("dns") +
                                        "ms tcp=" + nav.optInt("tcp") +
                                        "ms tls=" + nav.optInt("tls") +
                                        "ms ttfb=" + nav.optInt("ttfb") +
                                        "ms dcl=" + nav.optInt("domContentLoaded") +
                                        "ms load=" + nav.optInt("loadEventEnd") + "ms"
                                )
                            } else {
                                logLine("NAV unavailable")
                            }

                            val slow = payload.optJSONArray("topSlow")
                            if (slow != null && slow.length() > 0) {
                                val top = minOf(5, slow.length())
                                for (i in 0 until top) {
                                    val row = slow.getJSONObject(i)
                                    logLine(
                                        "SLOW[" + i + "] " +
                                            row.optInt("duration") + "ms " +
                                            row.optString("type") + " " +
                                            row.optString("name")
                                    )
                                }
                            }

                            logLine("Resource count=" + payload.optInt("resourceCount"))
                        }
                        "error" -> logLine("Perf JS error: " + payload.optString("message"))
                        else -> logLine("Unknown JS payload: " + payloadJson)
                    }
                } catch (e: Exception) {
                    logLine("Failed to parse JS payload: " + e.message)
                }
            }

            private fun logLine(line: String) {
                val stamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
                val entry = "[" + stamp + "] " + line
                Log.i("ReproHarness", entry)

                val maxChars = 16000
                if (binding.tvLog.text.length > maxChars) {
                    binding.tvLog.text = binding.tvLog.text.takeLast(maxChars / 2)
                }

                binding.tvLog.append(entry + "\\n")
            }

            override fun onDestroy() {
                binding.webView.destroy()
                super.onDestroy()
            }

            private inner class ReproBridge {
                @JavascriptInterface
                fun postMessage(payloadJson: String) {
                    runOnUiThread {
                        handleJsPayload(payloadJson)
                    }
                }
            }
        }
        '''
    )
    return template.replace("__PACKAGE_ID__", package_id)


def generate_android_harness(
    output_dir: Path,
    package_id: str,
    app_name: str,
    targets_payload: dict[str, Any],
) -> None:
    package_path = package_id.replace(".", "/")

    settings_gradle = textwrap.dedent(
        """\
        pluginManagement {
            repositories {
                google()
                mavenCentral()
                gradlePluginPortal()
            }
        }

        dependencyResolutionManagement {
            repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
            repositories {
                google()
                mavenCentral()
            }
        }

        rootProject.name = "WebViewReproHarness"
        include(":app")
        """
    )

    root_build_gradle = textwrap.dedent(
        """\
        plugins {
            id("com.android.application") version "8.5.2" apply false
            id("org.jetbrains.kotlin.android") version "1.9.24" apply false
        }
        """
    )

    app_build_gradle = textwrap.dedent(
        f"""\
        plugins {{
            id("com.android.application")
            id("org.jetbrains.kotlin.android")
        }}

        android {{
            namespace = "{package_id}"
            compileSdk = 34

            defaultConfig {{
                applicationId = "{package_id}"
                minSdk = 24
                targetSdk = 34
                versionCode = 1
                versionName = "1.0"
            }}

            buildTypes {{
                release {{
                    isMinifyEnabled = false
                    proguardFiles(
                        getDefaultProguardFile("proguard-android-optimize.txt"),
                        "proguard-rules.pro"
                    )
                }}
                debug {{
                    applicationIdSuffix = ".debug"
                    versionNameSuffix = "-debug"
                    isDebuggable = true
                }}
            }}

            compileOptions {{
                sourceCompatibility = JavaVersion.VERSION_17
                targetCompatibility = JavaVersion.VERSION_17
            }}

            kotlinOptions {{
                jvmTarget = "17"
            }}

            buildFeatures {{
                viewBinding = true
            }}
        }}

        dependencies {{
            implementation("androidx.core:core-ktx:1.13.1")
            implementation("androidx.appcompat:appcompat:1.7.0")
            implementation("com.google.android.material:material:1.12.0")
        }}
        """
    )

    gradle_properties = textwrap.dedent(
        """\
        org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8
        android.useAndroidX=true
        kotlin.code.style=official
        android.nonTransitiveRClass=true
        """
    )

    manifest_xml = textwrap.dedent(
        """\
        <?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android">

            <uses-permission android:name="android.permission.INTERNET" />

            <application
                android:allowBackup="false"
                android:label="@string/app_name"
                android:supportsRtl="true"
                android:theme="@style/Theme.ReproHarness"
                android:usesCleartextTraffic="true">
                <activity
                    android:name=".MainActivity"
                    android:exported="true"
                    android:windowSoftInputMode="adjustResize">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
            </application>

        </manifest>
        """
    )

    strings_xml = textwrap.dedent(
        f"""\
        <?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="app_name">{app_name}</string>
            <string name="load">Load</string>
            <string name="clear">Clear</string>
            <string name="summary_placeholder">No page loaded yet.</string>
        </resources>
        """
    )

    themes_xml = textwrap.dedent(
        """\
        <?xml version="1.0" encoding="utf-8"?>
        <resources>
            <style name="Theme.ReproHarness" parent="Theme.Material3.DayNight.NoActionBar" />
        </resources>
        """
    )

    activity_main_xml = textwrap.dedent(
        """\
        <?xml version="1.0" encoding="utf-8"?>
        <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
            android:layout_width="match_parent"
            android:layout_height="match_parent"
            android:orientation="vertical"
            android:padding="8dp">

            <LinearLayout
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:orientation="horizontal">

                <Spinner
                    android:id="@+id/urlSpinner"
                    android:layout_width="0dp"
                    android:layout_height="wrap_content"
                    android:layout_weight="1" />

                <Button
                    android:id="@+id/btnLoad"
                    android:layout_width="wrap_content"
                    android:layout_height="wrap_content"
                    android:layout_marginStart="8dp"
                    android:text="@string/load" />

                <Button
                    android:id="@+id/btnClear"
                    android:layout_width="wrap_content"
                    android:layout_height="wrap_content"
                    android:layout_marginStart="8dp"
                    android:text="@string/clear" />
            </LinearLayout>

            <TextView
                android:id="@+id/tvSummary"
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:layout_marginTop="8dp"
                android:text="@string/summary_placeholder"
                android:textAppearance="@style/TextAppearance.Material3.BodyMedium" />

            <ScrollView
                android:layout_width="match_parent"
                android:layout_height="140dp"
                android:layout_marginTop="8dp"
                android:fillViewport="true">

                <TextView
                    android:id="@+id/tvLog"
                    android:layout_width="match_parent"
                    android:layout_height="wrap_content"
                    android:fontFamily="monospace"
                    android:textSize="12sp" />
            </ScrollView>

            <WebView
                android:id="@+id/webView"
                android:layout_width="match_parent"
                android:layout_height="0dp"
                android:layout_marginTop="8dp"
                android:layout_weight="1" />
        </LinearLayout>
        """
    )

    files = {
        output_dir / "settings.gradle.kts": settings_gradle,
        output_dir / "build.gradle.kts": root_build_gradle,
        output_dir / "gradle.properties": gradle_properties,
        output_dir / "app/build.gradle.kts": app_build_gradle,
        output_dir / "app/proguard-rules.pro": "# Intentionally empty\n",
        output_dir / "app/src/main/AndroidManifest.xml": manifest_xml,
        output_dir / "app/src/main/res/values/strings.xml": strings_xml,
        output_dir / "app/src/main/res/values/themes.xml": themes_xml,
        output_dir / "app/src/main/res/layout/activity_main.xml": activity_main_xml,
        output_dir / f"app/src/main/java/{package_path}/MainActivity.kt": main_activity_template(package_id),
        output_dir / "app/src/main/assets/targets.json": json.dumps(targets_payload, indent=2) + "\n",
    }

    for path, content in files.items():
        write_text(path, content)


def generate_markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# APK Web Target Analysis",
        "",
        f"- Generated: `{report['generatedAtUtc']}`",
        f"- APK: `{report['apkPath']}`",
        f"- APK SHA256: `{report['apkSha256']}`",
        f"- Package: `{report.get('packageName') or 'unknown'}`",
        f"- Archive members scanned: `{report['stats']['scannedMembers']}`",
        f"- Archive members skipped: `{report['stats']['skippedMembers']}`",
        f"- Unique URLs found: `{report['stats']['uniqueUrls']}`",
        f"- Targets selected: `{report['stats']['targetsSelected']}`",
        "",
        "## Top Domains",
        "",
    ]

    if report["topDomains"]:
        lines.extend([f"- `{row['domain']}` (hits: {row['hits']})" for row in report["topDomains"]])
    else:
        lines.append("- None")

    lines.extend(["", "## Selected Targets", ""])
    if report["targets"]:
        lines.extend([f"- `{url}`" for url in report["targets"]])
    else:
        lines.append("- None")

    lines.extend(["", "## Top URL Hits", ""])
    if report["topUrls"]:
        for row in report["topUrls"]:
            sample_files = ", ".join(row["locations"])
            lines.append(
                f"- `{row['url']}` (hits: {row['hits']}; sample files: `{sample_files}`)"
            )
    else:
        lines.append("- None")

    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a debuggable Android WebView repro harness from an APK "
            "without altering the original APK"
        )
    )
    parser.add_argument("--apk", required=True, help="Path to source APK")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--max-targets", type=int, default=20, help="Max URLs in harness")
    parser.add_argument(
        "--max-member-size-mb",
        type=int,
        default=20,
        help="Skip APK entries larger than this during URL scan",
    )
    parser.add_argument("--package-id", default=DEFAULT_PACKAGE_ID, help="Generated app package")
    parser.add_argument("--app-name", default=DEFAULT_APP_NAME, help="Generated app name")
    parser.add_argument(
        "--extra-url",
        action="append",
        default=[],
        help="Force include additional URL (can repeat)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    apk_path = Path(args.apk).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()

    if not apk_path.exists() or not apk_path.is_file():
        raise SystemExit(f"APK does not exist: {apk_path}")

    out_dir.mkdir(parents=True, exist_ok=True)

    scan = scan_apk_for_urls(apk_path, args.max_member_size_mb)
    url_hits: Counter[str] = scan["hits"]
    locations: dict[str, list[str]] = scan["locations"]

    targets = choose_targets(url_hits, args.max_targets)
    for extra in args.extra_url:
        parsed = urlparse(extra)
        if parsed.scheme in {"http", "https"} and parsed.netloc and extra not in targets:
            targets.append(extra)

    if not targets:
        targets = ["https://example.com"]

    package_name = try_extract_package_name(apk_path)
    apk_hash = sha256_file(apk_path)
    generated_at = utc_now()

    top_urls: list[dict[str, Any]] = []
    for url, hit_count in url_hits.most_common(30):
        top_urls.append(
            {
                "url": url,
                "hits": hit_count,
                "locations": locations.get(url, []),
            }
        )

    report = {
        "generatedAtUtc": generated_at,
        "apkPath": str(apk_path),
        "apkSha256": apk_hash,
        "packageName": package_name,
        "stats": {
            "scannedMembers": scan["scanned_members"],
            "skippedMembers": scan["skipped_members"],
            "uniqueUrls": len(url_hits),
            "targetsSelected": len(targets),
        },
        "topDomains": summarize_domains(url_hits, limit=20),
        "targets": targets,
        "topUrls": top_urls,
    }

    analysis_dir = out_dir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    write_text(analysis_dir / "report.json", json.dumps(report, indent=2) + "\n")
    write_text(analysis_dir / "report.md", generate_markdown_report(report))

    targets_payload = {
        "generatedAtUtc": generated_at,
        "sourceApkName": apk_path.name,
        "sourceApkSha256": apk_hash,
        "sourcePackageName": package_name,
        "targets": targets,
    }

    project_dir = out_dir / "webview-repro-harness"
    generate_android_harness(
        output_dir=project_dir,
        package_id=args.package_id,
        app_name=args.app_name,
        targets_payload=targets_payload,
    )

    output_readme = textwrap.dedent(
        f"""\
        # Repro Output

        Generated: `{generated_at}`

        ## Contains
        - `analysis/report.json` and `analysis/report.md`
        - `webview-repro-harness/` Android project

        ## Run
        1. Open `webview-repro-harness` in Android Studio.
        2. Run debug variant on a device/emulator.
        3. Open `chrome://inspect/#devices` in desktop Chrome.
        4. Inspect the WebView and compare Network + Performance timelines.

        ## Notes
        - Source APK is not modified.
        - Add known URLs with `--extra-url https://...`.
        """
    )
    write_text(out_dir / "README.md", output_readme)

    print(f"Generated repro bundle at: {out_dir}")
    print(f"Analysis report: {analysis_dir / 'report.md'}")
    print(f"Android harness: {project_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
