# CSQTT-Keenetic — Keenetic MVP 0.2.0

Linux/Entware-менеджер для существующего нативного `csqtt-client` CSQTT 2.1.9.

## Что уже делает

- создаёт Linux TUN `csqtt0` через `/dev/net/tun` + `TUNSETIFF`;
- использует `IFF_TUN | IFF_NO_PI`;
- устанавливает MTU 1300;
- запускает существующий Rust `client` без его модификации;
- подключается к abstract Unix socket `@csqtt_tun_uds`;
- передаёт TUN FD через `SCM_RIGHTS` тем же способом, что Android-клиент;
- ждёт ACK `0x01`;
- включает `CSQTT_EVENTS=1`;
- разбирает `TUNCONF` и назначает серверный IPv4 на `csqtt0` как `/32`;
- автоматически создаёт и сохраняет `device_id/generation/salt` в `state.json`;
- поддерживает режим `vk_hash_mode=auto_api`: получает VK call/hash через `api.vk.ru`, передаёт hash в существующий Rust client и завершает созданные VK Calls при остановке;
- использует ту же логику количества Auto API calls, что Android CSQTT 2.1.9;
- поддерживает `vk_access_token` в конфиге или переменную окружения `CSQTT_VK_ACCESS_TOKEN`;
- содержит VK Web Panel на порту `2001`.

## VK Web Panel — автоматическая авторизация

Панель запускается вместе с менеджером и слушает `0.0.0.0:2001`. Порт выбран отдельно от HydraRoute Web Panel (`2000`).

Кнопка **«Войти через VK»** использует callback самой панели:

1. панель формирует OAuth URL с `/oauth/vk/callback`;
2. пользователь входит в свой VK-аккаунт;
3. VK возвращает `access_token` во fragment URL;
4. callback-страница автоматически извлекает token в браузере;
5. token сразу отправляется на `/api/vk/token`;
6. менеджер проверяет token через `users.get` API VK;
7. проверенный token, ID пользователя и срок действия атомарно сохраняются в `/opt/etc/csqтt/config.json`;
8. режим `vk_hash_mode` переводится в `auto_api`, если он ещё не задан.

**Копировать URL или access token вручную не требуется.**

### Требование VK OAuth

Для автоматического callback адрес:

```text
http(s)://<адрес-панели>:2001/oauth/vk/callback
```

должен быть разрешён как redirect URI для приложения VK `7793118`. Панель автоматически строит этот адрес из текущего Host. При необходимости адрес можно зафиксировать переменной окружения:

```sh
export CSQTT_VK_REDIRECT_URI="https://example.example/oauth/vk/callback"
```

Если используется HTTPS, перед панелью должен быть соответствующий reverse proxy/домен. Старый `https://oauth.vk.ru/blank.html` не позволяет обычной веб-странице панели автоматически прочитать fragment другого origin.

Панель не показывает token в статусе и не возвращает его через API. Конфигурация сохраняется атомарно с правами `0600`. HTTP-ответы панели помечаются `no-store` и `no-referrer`.

## Что пока НЕ делает

- не меняет default route;
- не делает policy routing;
- не включает весь LAN в туннель;
- не реализует CAPTCHA UI;
- не реализует HydraRoute failover.

## Установка на Entware

Скопировать новый `CSQTT-Keenetic` и существующий ARM64 `client` в `/opt/etc/csqтt/`.

```sh
mkdir -p /opt/etc/csqтt
chmod 755 /opt/etc/csqтt/CSQTT-Keenetic
chmod 755 /opt/etc/csqтt/client
```

Создать `/opt/etc/csqтt/config.json` по `config.example.json`.

Для Auto API нужен действующий VK access token. Его не следует публиковать в GitHub или отправлять в чат; можно задать его в `config.json` либо через `CSQTT_VK_ACCESS_TOKEN`.

Перед первым запуском проверить:

```sh
uname -m
ls -l /dev/net/tun
command -v ip || true
ls -l /opt/sbin/ip /opt/bin/ip 2>/dev/null || true
```

Запуск:

```sh
/opt/etc/csqтt/CSQTT-Keenetic -config /opt/etc/csqтt/config.json
```

При первом запуске менеджер сам создаст `/opt/etc/csqтt/state.json` с уникальными параметрами устройства.

## Важно

Для запуска нужны root-права и доступ к `/dev/net/tun`.

На первом тесте НЕ добавлять default route через `csqtt0`. Маршрутизация будет добавлена отдельным этапом после проверки TUN/CSQTT.

## Сборка

```text
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test ./...   # host test
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'
```

Цель: ARM64 / Entware `aarch64-k3.10`.
