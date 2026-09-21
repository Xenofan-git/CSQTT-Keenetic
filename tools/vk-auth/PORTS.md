# Port allocation

The VK auth component uses **TCP 18081** on Keenetic.

Reserved ports already used by the existing setup:
- HydraRoute upstream/service: TCP 2000
- CSQTT-Keenetic web panel: TCP 2001
- CSQTT-Keenetic local/service listener: TCP 9000
- Optional CSQTT-Keenetic UDP peer: UDP 46001
- Android CSQTT on VPS: UDP 46000
- Android CSQTT web panel on VPS: TCP 46002
- Reverse SSH to Keenetic: TCP 2222

VK auth intentionally does not use any of these ports.

The port is configurable through VK_AUTH_LISTEN, but 18081 is the default for this component.
