# CSQTT VK Auth for Entware

Lightweight ARM64 service for VK OAuth token capture.

No APK, Android WebView, Chromium, WPE, Playwright or Termux is required.

Flow:
1. Browser opens /api/vk/start.
2. Service creates a one-time state and redirects to VK OAuth.
3. VK redirects to VK_REDIRECT_URI.
4. The callback page reads the OAuth fragment locally in the browser and POSTs the token to /api/vk/token.
5. Entware validates the state and stores the token with mode 0600.
6. /api/vk/status exposes only non-secret status information.

The access token is never returned by the status endpoint and is not written to logs.

Configuration:
VK_AUTH_LISTEN defaults to 0.0.0.0:18080.
VK_REDIRECT_URI is required and must be accepted by the VK application.
VK_CLIENT_ID defaults to 7793118.
VK_OAUTH_SCOPE defaults to 1073737727.
VK_API_VERSION defaults to 5.199.
VK_TOKEN_FILE defaults to /opt/etc/csqtt/vk-token.json.

The redirect URI is intentionally configurable: the browser must execute the callback page on the configured origin. No browser injection is used.
