# Интеграция `tachyon-core` на Linux-серверах и в Docker

Руководство описывает развёртывание `tachyon-core` (v0.6.2) на Linux-серверах и шлюзах под управлением `systemd`, запуск в контейнерах Docker / `docker-compose`, локальную сборку статических артефактов через `core.Dockerfile` и системную настройку сетевого стека (`sysctl`).

## Выбор бинарного файла

| Артефакт релиза | Тип линковки | Рекомендуемый сценарий |
|---|---|---|
| `tachyon-core-x86_64-v0.6.2.tar.gz` | Статический `musl` (`+crt-static`) | Любые дистрибутивы Linux (включая старые glibc), минимальные контейнеры (`scratch`, `alpine`, `distroless`). |
| `tachyon-core-aarch64-v0.6.2.tar.gz` | Статический `musl` (`+crt-static`) | ARM64-серверы (AWS Graviton, Oracle Ampere, Raspberry Pi 4/5, NanoPi). |
| `tachyon-core-linux-amd64-v0.6.2.tar.gz` | Динамический `glibc` | Современные x86_64-дистрибутивы Linux (Debian 12+, Ubuntu 22.04+, RHEL 9+). |

Установка бинарника и каталогов конфигурации:

```bash
tar -xzf tachyon-core-x86_64-v0.6.2.tar.gz
sudo install -m 0755 tachyon-core-x86_64-v0.6.2 /usr/local/bin/tachyon-core
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tachyon
sudo mkdir -p /etc/tachyon-core /var/lib/tachyon-core /var/log/tachyon-core
sudo chown -R tachyon:tachyon /var/lib/tachyon-core /var/log/tachyon-core
```

---

## Развёртывание через `systemd`

Создайте unit-файл `/etc/systemd/system/tachyon-core.service`:

```ini
[Unit]
Description=tachyon-core routing and proxy engine
Documentation=https://github.com/Dushnilin/tachyon-core
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=tachyon
Group=tachyon
WorkingDirectory=/var/lib/tachyon-core

# Предварительная проверка конфигурации до запуска
ExecStartPre=/usr/local/bin/tachyon-core check -c /etc/tachyon-core/config.json -D /var/lib/tachyon-core
ExecStart=/usr/local/bin/tachyon-core run -c /etc/tachyon-core/config.json -D /var/lib/tachyon-core
ExecReload=/bin/kill -HUP $MAINPID

# Минимально необходимые привилегии для портов <1024, TUN, TProxy и SO_MARK
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# Ограничения и надёжность
LimitNOFILE=65535
OOMScoreAdjust=-500
Restart=on-failure
RestartSec=5s
TimeoutStopSec=25s

# Опциональные параметры времени выполнения
Environment=TACHYON_TCP_CONGESTION=bbr
Environment=TACHYON_RULESET_SOFT_START=1

[Install]
WantedBy=multi-user.target
```

> **Примечание о `TimeoutStopSec=25s`:** при остановке `tachyon-core` выполняет корректное освобождение QUIC- и UDP-сокетов с контрольным интервалом watchdog `20 с`. Значение `25s` даёт ядру гарантированное время на сброс `cache.db` и закрытие сокетов до отправки `SIGKILL`.

Если режим `tun` и `tproxy` не используется (например, сервер принимает только VLESS/Hysteria2/TUIC на портах `443` и выше), достаточно оставить только `CAP_NET_BIND_SERVICE`.

Активация и управление службой:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tachyon-core

# Безопасное обновление конфигурации без простоя:
sudo tachyon-core check -c /etc/tachyon-core/config.json
sudo tachyon-core reload-preview --current /etc/tachyon-core/config.json /etc/tachyon-core/config.new.json
sudo mv /etc/tachyon-core/config.new.json /etc/tachyon-core/config.json
sudo systemctl reload tachyon-core

# Просмотр логов (если log.output не переопределён на файл)
journalctl -u tachyon-core -f
```

---

## Запуск в Docker и `docker-compose`

### Минимальный runtime-образ

Статический `musl`-бинарник не требует внешней `libc` и корневых сертификатов хоста, поэтому образ можно собирать на базе `alpine` (если нужна отладочная оболочка и `iproute2`) или `scratch`.

```dockerfile
FROM alpine:3.21

RUN apk add --no-cache iproute2 tzdata \
    && mkdir -p /etc/tachyon-core /var/lib/tachyon-core

COPY tachyon-core /usr/local/bin/tachyon-core
RUN chmod 0755 /usr/local/bin/tachyon-core

WORKDIR /var/lib/tachyon-core
ENTRYPOINT ["/usr/local/bin/tachyon-core"]
CMD ["run", "-c", "/etc/tachyon-core/config.json", "-D", "/var/lib/tachyon-core"]
```

### Вариант 1: Серверный узел (прокси-инбаунды, без TUN)

```yaml
services:
  tachyon-core:
    image: tachyon-core:0.6.2
    container_name: tachyon-core
    restart: unless-stopped
    ports:
      - "443:443/tcp"
      - "443:443/udp"
      - "127.0.0.1:9090:9090/tcp"
    volumes:
      - ./config.json:/etc/tachyon-core/config.json:ro
      - ./certs:/etc/tachyon-core/certs:ro
      - tachyon_state:/var/lib/tachyon-core
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
    environment:
      - TACHYON_TCP_CONGESTION=bbr
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: "2.0"

volumes:
  tachyon_state:
```

> `tachyon-core` автоматически читает лимиты `cgroup` v1/v2 (`memory.max`, `cpu.max`) внутри контейнера и подстраивает число потоков Tokio, размеры буферов и пороги давления памяти под квоту контейнера, а не хоста.

### Вариант 2: Шлюз с TUN или TProxy (`network_mode: host`)

Для работы с `/dev/net/tun`, `auto_route` или `tproxy` контейнеру требуются сетевое пространство имён хоста, проброс `/dev/net/tun` и права `NET_ADMIN`/`NET_RAW`:

```yaml
services:
  tachyon-gateway:
    image: tachyon-core:0.6.2
    container_name: tachyon-gateway
    restart: unless-stopped
    network_mode: host
    devices:
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - NET_BIND_SERVICE
    volumes:
      - ./config.json:/etc/tachyon-core/config.json:ro
      - tachyon_state:/var/lib/tachyon-core
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
    environment:
      - TACHYON_RULESET_SOFT_START=1

volumes:
  tachyon_state:
```

Горячая перезагрузка в контейнере без перезапуска:

```bash
docker exec tachyon-core tachyon-core check -c /etc/tachyon-core/config.json
docker kill --signal=HUP tachyon-core
```

### Локальная сборка статического бинарника через `core.Dockerfile`

В корне репозитория расположен `core.Dockerfile` (`FROM rust:1.92-bookworm` с `musl-tools` и `zstd`), предназначенный для воспроизводимой сборки статических релизных бинарников на хосте:

```bash
docker build -t tachyon-core-build -f core.Dockerfile .
docker run --rm -v "$PWD:/src" -w /src tachyon-core-build \
  cargo build -p core-cli --release --target x86_64-unknown-linux-musl
```

> Не задавайте глобальную переменную окружения `RUSTFLAGS` при вызове `cargo build`: в Cargo она перетирает целевые массивы `rustflags` из `.cargo/config.toml` (включая аппаратные флаги ARMv8 AES/PMULL/NEON и опции линковщика).

---

## Сетевые параметры ядра (`sysctl`)

Создайте файл `/etc/sysctl.d/99-tachyon-core.conf` для серверного или шлюзового развёртывания:

```ini
# Форвардинг (обязательно для шлюзов с TUN / TProxy / WireGuard)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Управление перегрузкой TCP (BBR + FQ pacing)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Буферы сокетов (особенно критично для QUIC: Hysteria2, TUIC, MASQUE, Naive H3)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# Очереди и быстродействие под высокой нагрузкой
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 4096
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
```

Применение настроек:

```bash
sudo sysctl --system
```

---

## Клиентский и серверный деплой: контрольный список

### Серверный узел (мультипротокольный вход)

- Выберите инбаунды под задачу (см. [Пример мультипротокольного сервера](../06-examples/04-server-multiplex.json)).
- Привязывайте `experimental.clash_api.external_controller` строго к `127.0.0.1:9090` (или к внутреннему WireGuard/Tailscale IP) и всегда задавайте длинный `secret`.
- Для мониторинга настройте сбор Prometheus с `GET /metrics` и проверку жизнеспособности с `GET /tachyon/health`.
- Для учёта клиентского трафика и отключения пользователей используйте `GET /tachyon/stats?reset=1` и `POST /tachyon/kick`.
- При обновлении списка `users` у инбаундов `vless`, `trojan`, `vmess`, `hysteria2`, `tuic`, `anytls` перезагрузка через `SIGHUP` или `PUT /configs` выполняется `in_place` без разрыва существующих клиентских сессий.

### Клиентский шлюз (Linux-машина или LAN-роутер)

- Для локального клиента без прав `root` используйте инбаунд `mixed` (`127.0.0.1:2080`).
- Для перехвата всего трафика хоста используйте `tun` с `auto_route: true` и `strict_route: true` (требуется `CAP_NET_ADMIN` и `/dev/net/tun`).
- Проверяйте корректность маршрутизации и отсутствие утечек через `POST /tachyon/route-check`, `POST /tachyon/connection-test` и `GET /tachyon/leak`.
