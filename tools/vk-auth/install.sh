#!/bin/sh
set -eu

BASE=/opt/etc/csqtt
BIN=/opt/bin/csqtt-vk-auth
INIT=/opt/etc/init.d/S98csqtt-vk-auth

mkdir -p "$BASE" /opt/bin /opt/etc/init.d
install -m 0755 csqtt-vk-auth "$BIN"
install -m 0755 S98csqtt-vk-auth "$INIT"

if [ ! -f "$BASE/vk-auth.env" ]; then
cat > "$BASE/vk-auth.env" <<'EOF'
VK_AUTH_LISTEN=0.0.0.0:18080
VK_REDIRECT_URI=http://ROUTER_IP:18080/api/vk/callback
VK_CLIENT_ID=7793118
VK_OAUTH_SCOPE=1073737727
VK_API_VERSION=5.199
VK_TOKEN_FILE=/opt/etc/csqtt/vk-token.json
EOF
chmod 600 "$BASE/vk-auth.env"
fi

echo "Installed. Edit $BASE/vk-auth.env and start:"
echo "$INIT start"
