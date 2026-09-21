# wpe-vk-auth

Minimal Linux/Entware-side WPE WebKit probe for CSQTT-Keenetic.

## Target

- aarch64
- Entware/Linux
- WPE WebKit 2.54+
- WPEPlatform 2.0
- headless platform for the first validation stage

This is not Android WebView and does not use Android SDK/Java.

## Why WPE

VK implicit OAuth returns access_token in the URL fragment of
oauth.vk.ru/blank.html. The fragment is visible to page JavaScript but
is not sent to an HTTP server. Therefore the token must be observed from
inside the browser engine.

The Android project in this repository is only a behavioral reference.
The Entware implementation is native C against WPE WebKit.

## First milestone

Build and run:

    WPE_PLATFORM=headless ./wpe-vk-auth https://example.com/

The probe evaluates JavaScript after page load and reports the URL seen by
JavaScript. It deliberately never prints a real VK access token.

## Important

Headless mode is only the first engineering milestone. It cannot display a
CAPTCHA to the user. After the engine is proven on Keenetic, we will add the
smallest practical interactive path for manual CAPTCHA/login and then connect
the token to the existing CSQTT /api/vk/token endpoint.

Do not modify the existing CSQTT-Keenetic binary or Web Panel while testing
this component.
