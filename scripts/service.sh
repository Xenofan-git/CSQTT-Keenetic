#!/bin/sh
# Install/upgrade CSQTT-Keenetic Entware service and watchdog.
set -eu
BASE=/opt/etc/csqtt
INIT=/opt/etc/init.d/S99csqtt
mkdir -p "$BASE" /opt/etc/init.d
cp "$BASE/S99csqtt" "$INIT"
cp "$BASE/watchdog.sh" "$BASE/watchdog.sh"
cp "$BASE/service.sh" "$BASE/service.sh"
chmod 755 "$INIT" "$BASE/watchdog.sh" "$BASE/service.sh"
echo "CSQTT service installed: $INIT"
echo "Use: $INIT {start|stop|restart|status}"
