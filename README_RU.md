# CSQTT-Keenetic — Keenetic MVP 0.1.1

Первый Linux/Entware менеджер для существующего `csqtt-client` CSQTT 2.1.9.

## Что делает

- создаёт Linux TUN `csqtt0` через `/dev/net/tun` + `TUNSETIFF`;
- использует `IFF_TUN | IFF_NO_PI`;
- устанавливает MTU 1300;
- запускает существующий Rust `client` без его модификации;
- подключается к abstract Unix socket `@csqtt_tun_uds`;
- передаёт TUN FD через `SCM_RIGHTS` тем же способом, что Android-клиент;
- ждёт ACK `0x01`;
- включает `CSQTT_EVENTS=1`;
- разбирает `TUNCONF` и назначает серверный IPv4 на `csqtt0` как `/32`;
- корректно замечает преждевременный выход `client` во время передачи FD;
- ищет `ip` в `/opt/sbin`, `/opt/bin`, системных путях и PATH.

## Что пока НЕ делает

- не меняет default route;
- не делает policy routing;
- не включает весь LAN в туннель;
- не реализует Web Panel;
- не реализует Auto API/CAPTCHA UI;
- не реализует HydraRoute failover.

Это намеренно: первый тест должен подтвердить работу существующего Rust-транспорта на Keenetic отдельно от маршрутизации.

## Установка на Entware

Скопировать `CSQTT-Keenetic` и существующий ARM64 `client` в `/opt/etc/csqtt/`.

```sh
mkdir -p /opt/etc/csqtt
chmod 755 /opt/etc/csqtt/CSQTT-Keenetic
chmod 755 /opt/etc/csqtt/client
```

Создать `/opt/etc/csqtt/config.json` по `config.example.json`.

Перед первым запуском проверить:

```sh
uname -m
ls -l /dev/net/tun
command -v ip || true
ls -l /opt/sbin/ip /opt/bin/ip 2>/dev/null || true
```

Запуск:

```sh
/opt/etc/csqtt/CSQTT-Keenetic -config /opt/etc/csqtt/config.json
```

## Важно

Для запуска нужны root-права и доступ к `/dev/net/tun`.

На первом тесте НЕ добавлять default route через `csqtt0`. Маршрутизация будет добавлена отдельным этапом после проверки TUN/CSQTT.

## Проверка сборки

Сборка проверена локально:

```text
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'
```

Цель: ARM64 / Entware `aarch64-k3.10`.
