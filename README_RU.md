# CSQTT-Keenetic — Keenetic MVP 0.2.0

Linux/Entware-менеджер для существующего нативного `csqtt-client` CSQTT 2.1.9.

## VK Web Panel

Панель работает на порту `2001`, отдельно от HydraRoute (`2000`). Кнопка **«Войти через VK»** использует `/oauth/vk/callback`: после входа VK возвращает `access_token` во fragment URL, callback автоматически извлекает его и отправляет на `/api/vk/token`. Менеджер проверяет токен через `users.get` и сохраняет проверенный токен, ID пользователя и срок действия в `/opt/etc/csqtt/config.json` с правами `0600`.

**Копировать URL или access token вручную не требуется.**

Для автоматического callback адрес `http(s)://<адрес-панели>:2001/oauth/vk/callback` должен быть разрешён как redirect URI приложения VK `7793118`. При необходимости адрес можно зафиксировать через `CSQTT_VK_REDIRECT_URI`.

## Что делает менеджер

- создаёт Linux TUN `csqtt0`;
- запускает существующий ARM64 Rust client CSQTT 2.1.9;
- передаёт TUN FD через abstract Unix socket и `SCM_RIGHTS`;
- поддерживает `vk_hash_mode=auto_api`;
- создаёт и сохраняет `device_id/generation/salt` в `state.json`;
- содержит VK Web Panel.

## Что пока не делает

- не меняет default route;
- не делает policy routing;
- не включает весь LAN в туннель;
- не реализует CAPTCHA UI;
- не реализует HydraRoute failover.

## Установка на Entware

```sh
mkdir -p /opt/etc/csqtt
chmod 755 /opt/etc/csqtt/CSQTT-Keenetic
chmod 755 /opt/etc/csqtt/client
```

Создать `/opt/etc/csqtt/config.json` по `config.example.json`.

Запуск:

```sh
/opt/etc/csqtt/CSQTT-Keenetic -config /opt/etc/csqtt/config.json
```

При первом запуске менеджер создаст `/opt/etc/csqtt/state.json`.

## Важно

Для запуска нужны root-права и доступ к `/dev/net/tun`. На первом тесте НЕ добавлять default route через `csqtt0`.

## Сборка

```text
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'
```

Цель: ARM64 / Entware `aarch64-k3.10`.
