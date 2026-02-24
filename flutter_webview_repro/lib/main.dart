import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

const String _defaultStartUrl = String.fromEnvironment(
  'START_URL',
  defaultValue: 'https://www.kmart.com.au',
);

const String _defaultUserAgent =
    'Mozilla/5.0 (Linux; Android 12; K) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36';

const List<String> _defaultBlockPatterns = <String>[
  'analytics.google.com',
  'accounts.google.com',
  'doubleclick.net',
  'www.google.com/pagead',
  'ccm/collect',
  'behavioral_action',
  'newrelic',
  'braze',
  'pinterest',
  'facebook.com/tr',
  'connect.facebook.net',
  'googletagmanager.com',
  'google-analytics.com',
];

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ReproApp());
}

class ReproApp extends StatelessWidget {
  const ReproApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Kmart-like WebView Repro',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF0E6251)),
      ),
      home: const ReproScreen(),
    );
  }
}

class ReproScreen extends StatefulWidget {
  const ReproScreen({super.key});

  @override
  State<ReproScreen> createState() => _ReproScreenState();
}

class _ReproScreenState extends State<ReproScreen> {
  final TextEditingController _urlController = TextEditingController(
    text: _defaultStartUrl,
  );

  InAppWebViewController? _controller;
  double _progress = 0;
  bool _blockTracking = false;
  bool _canGoBack = false;
  bool _canGoForward = false;
  int _blockedRequestCount = 0;
  final List<String> _logs = <String>[];

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  String? _normalizeUrl(String input) {
    final String trimmed = input.trim();
    if (trimmed.isEmpty) {
      return null;
    }
    if (trimmed.startsWith('https://') || trimmed.startsWith('http://')) {
      return trimmed;
    }
    if (trimmed.contains('://')) {
      return null;
    }
    return 'https://$trimmed';
  }

  Future<void> _loadFromInput() async {
    final InAppWebViewController? controller = _controller;
    if (controller == null) {
      return;
    }

    final String? normalized = _normalizeUrl(_urlController.text);
    if (normalized == null) {
      _snackbar('Invalid URL. Use https://host/path or host/path');
      return;
    }

    _addLog('Loading $normalized');
    await controller.loadUrl(urlRequest: URLRequest(url: WebUri(normalized)));
  }

  void _snackbar(String text) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(text)));
  }

  void _addLog(String message) {
    final String ts = DateTime.now().toIso8601String();
    _logs.insert(0, '[$ts] $message');
    if (_logs.length > 200) {
      _logs.removeRange(200, _logs.length);
    }
  }

  Future<void> _refreshNavState() async {
    final InAppWebViewController? controller = _controller;
    if (controller == null) {
      return;
    }

    final bool back = await controller.canGoBack();
    final bool forward = await controller.canGoForward();

    if (!mounted) {
      return;
    }

    setState(() {
      _canGoBack = back;
      _canGoForward = forward;
    });
  }

  bool _isBlockedUrl(String url) {
    final String u = url.toLowerCase();
    for (final String pattern in _defaultBlockPatterns) {
      if (u.contains(pattern.toLowerCase())) {
        return true;
      }
    }
    return false;
  }

  Future<WebResourceResponse?> _handleIntercept(WebResourceRequest request) async {
    if (!_blockTracking) {
      return null;
    }

    final String url = request.url.toString();
    if (!_isBlockedUrl(url)) {
      return null;
    }

    _blockedRequestCount += 1;
    _addLog('BLOCKED: $url');

    if (mounted) {
      setState(() {});
    }

    return WebResourceResponse(
      contentType: 'application/json',
      statusCode: 200,
      reasonPhrase: 'OK',
      headers: <String, String>{
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json',
      },
      data: Uint8List.fromList('{}'.codeUnits),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Kmart-like WebView Repro'),
        actions: <Widget>[
          IconButton(
            tooltip: 'Reload',
            icon: const Icon(Icons.refresh),
            onPressed: () => _controller?.reload(),
          ),
        ],
      ),
      body: Column(
        children: <Widget>[
          Padding(
            padding: const EdgeInsets.fromLTRB(10, 10, 10, 6),
            child: Row(
              children: <Widget>[
                Expanded(
                  child: TextField(
                    controller: _urlController,
                    decoration: const InputDecoration(
                      border: OutlineInputBorder(),
                      isDense: true,
                      hintText: 'Enter URL or host',
                    ),
                    keyboardType: TextInputType.url,
                    textInputAction: TextInputAction.go,
                    onSubmitted: (_) => _loadFromInput(),
                  ),
                ),
                const SizedBox(width: 8),
                FilledButton(
                  onPressed: _loadFromInput,
                  child: const Text('Go'),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8),
            child: Row(
              children: <Widget>[
                IconButton(
                  tooltip: 'Back',
                  onPressed: _canGoBack
                      ? () async {
                          await _controller?.goBack();
                          await _refreshNavState();
                        }
                      : null,
                  icon: const Icon(Icons.arrow_back),
                ),
                IconButton(
                  tooltip: 'Forward',
                  onPressed: _canGoForward
                      ? () async {
                          await _controller?.goForward();
                          await _refreshNavState();
                        }
                      : null,
                  icon: const Icon(Icons.arrow_forward),
                ),
                const SizedBox(width: 8),
                const Text('Block trackers'),
                Switch(
                  value: _blockTracking,
                  onChanged: (bool value) {
                    setState(() {
                      _blockTracking = value;
                    });
                  },
                ),
                const Spacer(),
                Text('Blocked: $_blockedRequestCount'),
              ],
            ),
          ),
          if (_progress < 1)
            LinearProgressIndicator(
              value: _progress,
              minHeight: 3,
            ),
          Expanded(
            child: InAppWebView(
              initialUrlRequest: URLRequest(url: WebUri(_defaultStartUrl)),
              initialSettings: InAppWebViewSettings(
                javaScriptEnabled: true,
                cacheEnabled: true,
                clearCache: false,
                clearSessionCache: false,
                useShouldInterceptRequest: true,
                isInspectable: true,
                useHybridComposition: true,
                domStorageEnabled: true,
                supportZoom: false,
                mediaPlaybackRequiresUserGesture: false,
                userAgent: _defaultUserAgent,
              ),
              onWebViewCreated: (InAppWebViewController controller) {
                _controller = controller;
                _addLog('WebView created');
              },
              onLoadStart: (InAppWebViewController controller, WebUri? url) {
                final String next = url?.toString() ?? '';
                if (next.isNotEmpty) {
                  _urlController.text = next;
                }
                _addLog('onLoadStart: $next');
                setState(() {
                  _progress = 0;
                });
              },
              onProgressChanged: (InAppWebViewController controller, int p) {
                setState(() {
                  _progress = p / 100;
                });
              },
              onLoadStop: (
                InAppWebViewController controller,
                WebUri? url,
              ) async {
                _addLog('onLoadStop: ${url?.toString() ?? ''}');
                await _refreshNavState();
                if (mounted) {
                  setState(() {
                    _progress = 1;
                  });
                }
              },
              onReceivedError: (
                InAppWebViewController controller,
                WebResourceRequest request,
                WebResourceError error,
              ) {
                _addLog('ERROR ${error.type} desc=${error.description}');
                if (mounted) {
                  setState(() {});
                }
              },
              shouldInterceptRequest: (
                InAppWebViewController controller,
                WebResourceRequest request,
              ) async {
                return _handleIntercept(request);
              },
            ),
          ),
          Container(
            height: 130,
            width: double.infinity,
            color: const Color(0xFFF4F6F8),
            padding: const EdgeInsets.fromLTRB(10, 8, 10, 8),
            child: ListView.builder(
              itemCount: _logs.length.clamp(0, 8),
              itemBuilder: (BuildContext context, int index) {
                return Text(
                  _logs[index],
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontSize: 11),
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}
