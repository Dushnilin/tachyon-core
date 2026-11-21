# Готовые примеры конфигураций

Каталог содержит семь полных JSON-конфигураций для основных сценариев эксплуатации `tachyon-core`: от маршрутизатора OpenWrt и настольного TUN-клиента до мультипротокольного сервера, туннельных эндпоинтов и компактного профиля под мобильные устройства. Все файлы проверены валидатором схемы `tachyon-core check -c`.

> [!NOTE]
> Все UUID, ключи REALITY, ключи WireGuard/AmneziaWG, ключи Shadowsocks 2022, пароли, токены `auth_key` и встроенные TLS-сертификаты в примерах являются тестовыми заглушками. Перед развёртыванием замените их собственными значениями с помощью подкоманд `tachyon-core generate`.

## Обзор примеров

| Файл | Сценарий | Основные компоненты |
|:---|:---|:---|
| [`01-openwrt-tproxy-router.json`](01-openwrt-tproxy-router.json) | Маршрутизатор OpenWrt с прозрачным перехватом | `tproxy` (IPv4/IPv6), DNS (DoH + `local` + `fakeip`), удалённый `rule_set` формата `.trs` (`mmap`), `vless` REALITY (`chrome_pq` + `X25519MLKEM768`), резервный `desync` (`preset: "adaptive"`), `clash_api`, `cache_file` в `/tmp/tachyon-core/cache.db` |
| [`02-desktop-tun-client.json`](02-desktop-tun-client.json) | Настольный клиент (Linux / Windows / macOS) | `tun` (`stack: "smoltcp"`, `auto_route`, `gso`), `mixed` SOCKS/HTTP, `dns` с FakeIP, `vless` REALITY + транспорт `xhttp` с пулом `xmux`, `urltest`-балансировщик, раздельная маршрутизация |
| [`03-adaptive-desync-split.json`](03-adaptive-desync-split.json) | Локальная сетевая оптимизация без внешнего туннеля | `mixed` + `tun`, `desync` (`preset: "adaptive"`, `auto_tune`, `quic_desync`, `udp_out_range`), раздельная маршрутизация и расписание `time_window` |
| [`04-server-multiplex.json`](04-server-multiplex.json) | Мультипротокольный серверный узел | Серверные инбаунды `vless` (REALITY + Vision), `hysteria2` (`salamander`), `tuic` v5 (`bbr`), `anytls` (`padding_scheme`), `shadowsocks` (2022 multi-user), `fptn`, inline-сертификаты TLS, защита от доступа к частным сетям |
| [`05-wireguard-awg-tailscale.json`](05-wireguard-awg-tailscale.json) | Туннельные эндпоинты AmneziaWG и Tailscale | `endpoints`: `wireguard` с расширенными параметрами AmneziaWG (`jc`/`jmin`/`jmax`, `s1`–`s4`, `h1`–`h4`, `i1`–`i5`) и ротацией портов (`server_ports`, `hop_interval`), `tailscale` (Exit Node + MagicDNS) |
| [`06-chains-and-balancers.json`](06-chains-and-balancers.json) | Многоступенчатые цепочки и нативные балансировщики | Двухступенчатая связка через `detour`, декларативная трёхступенчатая цепочка `chain`, балансировщики `urltest` в режимах `sticky` (HRW-хеширование) и `priority` (иерархические `tiers`), `selector` с `auto_failover` |
| [`07-mobile-embedded-tun.json`](07-mobile-embedded-tun.json) | Мобильный клиент (iOS 50 MiB Jetsam / Android `VpnService`) | Компактный `tun` (`mtu: 1400`, `udp_nat_max: 256`, `smoltcp`), `ipv4_only` DNS с FakeIP, одиночный `vless` REALITY (`ios`), минимальные настройки `cache_file` и журналирования |

## Назначение и особенности каждого примера

### 1. Роутер OpenWrt (`01-openwrt-tproxy-router.json`)

- Инбаунд `tproxy` слушает `::` на порту `7893` (dual-stack IPv4/IPv6) с режимом UDP NAT `endpoint_independent`.
- Поле `route.default_mark: 255` задаёт единый `fwmark` (`0xff`) для всех исходящих сокетов ядра на Linux/OpenWrt, исключая петли маршрутизации в правилах `nftables`/`ip rule`. При необходимости отдельного маркера для конкретного аутбаунда на Linux задаётся `routing_mark` непосредственно в объекте аутбаунда.
- Удалённый набор правил `tunnel-domains` использует бинарный формат `trs` с отображением в память (`"mmap": true`), что сокращает потребление ОЗУ на роутерах с 64–128 MiB RAM.
- Основной аутбаунд `proxy-vless-pq` использует VLESS + `xtls-rprx-vision` + REALITY с профилем `chrome_pq` и гибридным постквантовым обменом `support_x25519mlkem768: true`. В группе `egress-select` настроен резервный `desync` (`preset: "adaptive"`) с `auto_failover: true`.
- Журнал и `cache.db` размещены в `/tmp/tachyon-core/` (tmpfs в ОЗУ) для защиты флеш-памяти роутера от износа. Подробнее см. [Интеграция с OpenWrt](../05-integration/openwrt.md).

### 2. Настольный клиент (`02-desktop-tun-client.json`)

- Одновременно поднимает системный `tun`-интерфейс на пользовательском стеке `smoltcp` (`auto_route: true`, `strict_route: true`, `gso: true`) и локальный `mixed`-прокси на `127.0.0.1:1080` для приложений с ручной настройкой прокси.
- Демонстрирует `vless` REALITY поверх транспорта `xhttp` (`mode: "stream-up"`) с настроенным пулом мультиплексирования `xmux` (`max_concurrency`, `c_max_reuse_times`, `h_max_request_times`, `h_max_reusable_secs`).
- Балансировщик `urltest` (`auto-best`) периодически проверяет узлы `vless-xhttp-eu` и `vless-vision-eu`, переключаясь на узел с наименьшей задержкой в пределах `tolerance: 50`.

### 3. Локальная сетевая оптимизация (`03-adaptive-desync-split.json`)

- Не требует внешнего прокси-сервера: трафик, подпадающий под правила, уходит через аутбаунд `desync` (`preset: "adaptive"`, `auto_tune: true`, `quic_desync: true`, `udp_out_range: "1-2"`).
- Показывает применение условия `time_window` (`"mon-fri 09:00-18:00 UTC+3"`): в рабочие часы указанные домены направляются через `direct`, в остальное время — через `desync-adaptive`.

### 4. Мультипротокольный сервер (`04-server-multiplex.json`)

- Объединяет в одном процессе шесть серверных инбаундов:
  - `vless` + REALITY + `xtls-rprx-vision` (TCP `443`);
  - `hysteria2` с обфускацией `salamander` (UDP `8443`);
  - `tuic` v5 с управлением перегрузкой `bbr` (UDP `9443`);
  - `anytls` с настраиваемой `padding_scheme` (TCP `10443`);
  - `shadowsocks` с методом `2022-blake3-aes-128-gcm` и многопользовательским списком `users` (TCP/UDP `11443`);
  - `fptn` с выделением подсети `10.10.0.0/16` (TCP `12443`).
- Для прохождения автономной валидации `tachyon-core check -c` без файлов на диске сертификат и ключ TLS встроены в массивы `tls.certificate` и `tls.key`. В промышленной эксплуатации рекомендуется вынести их в файлы и указать `tls.certificate_path` и `tls.key_path`.
- Маршрутизатор отклоняет обращения к частным сетям (`ip_is_private: true`, `"action": "reject"`), предотвращая использование сервера для сканирования внутренней инфраструктуры.

### 5. Туннельные эндпоинты AmneziaWG и Tailscale (`05-wireguard-awg-tailscale.json`)

- Эндпоинт `ep-awg` (`type: "wireguard"`) задаёт полный набор параметров AmneziaWG 2.0/3.x (`jc`, `jmin`, `jmax`, `s1`–`s4`, диапазоны заголовков `h1`–`h4`, шаблоны инициализации `i1`–`i5`), а также ротацию портов на пире (`server_ports`, `hop_interval: "30s"`).
- Эндпоинт `ep-tailscale` (`type: "tailscale"`) подключается к сети Tailscale в режиме Exit Node (`exit_node: "100.64.0.1"`, `exit_node_allow_lan_access: true`) и интегрирован с DNS-транспортом `type: "tailscale"` для разрешения имён `.ts.net` через MagicDNS.

### 6. Многоступенчатые цепочки и балансировщики (`06-chains-and-balancers.json`)

- Показывает два способа построения каскадных маршрутов:
  - двухступенчатый туннель через поле `detour` (`hop-detour-exit` поверх `hop-entry`);
  - декларативная трёхступенчатая цепочка `type: "chain"` (`hop-entry` -> `hop-mid` -> `hop-final`).
- Демонстрирует расширенные режимы `urltest`:
  - `lb-sticky` (`mode: "sticky"`) с консистентным хешированием потоков по `["source_ip", "domain"]` и окном пула `pool: 2`, `pool_tolerance: 80`;
  - `lb-priority-tiers` (`mode: "priority"`) с разбиением узлов на эшелоны `balancer.tiers` (переход на резервный эшелон только при недоступности основного).
- Группа `egress-main` (`selector`) объединяет балансировщики и цепочки с включённым `auto_failover: true`.

### 7. Мобильный и встраиваемый TUN-клиент (`07-mobile-embedded-tun.json`)

- Ориентирован на жёсткие лимиты памяти (`50 MiB` Jetsam в iOS `NEPacketTunnelProvider` и фоновые процессы Android `VpnService`).
- Ограничивает MTU до `1400`, таблицу UDP NAT до `udp_nat_max: 256` с `udp_timeout: "1m"`, отключает отдельный кэш DNS-серверов (`independent_cache: false`) и запись RDRC (`store_rdrc: false`), а уровень логирования снижен до `warn`. Подробнее см. [Интеграция с iOS и Android](../05-integration/mobile-ios-android.md).

## Проверка конфигураций

Проверьте любой пример локальным бинарником `tachyon-core`:

```bash
tachyon-core check -c docs/06-examples/01-openwrt-tproxy-router.json
```

Пакетная проверка всех примеров в Linux / macOS:

```bash
for f in docs/06-examples/*.json; do
  tachyon-core check -c "$f" && echo "OK: $f"
done
```

Пакетная проверка всех примеров в PowerShell (Windows):

```powershell
Get-ChildItem docs/06-examples/*.json | ForEach-Object {
  tachyon-core check -c $_.FullName
  if ($LASTEXITCODE -eq 0) { "OK: $($_.Name)" }
}
```

При успешной валидации команда завершается с кодом возврата `0` без вывода ошибок.

## Генерация рабочих ключей перед запуском

```bash
tachyon-core generate uuid                                    # UUID для VLESS / TUIC
tachyon-core generate reality-keypair                         # пара ключей X25519 для REALITY
tachyon-core generate wg-keypair                              # пара ключей WireGuard / AmneziaWG
tachyon-core generate rand --base64 16                        # ключ 16 байт для Shadowsocks 2022 AES-128-GCM
tachyon-core generate tls-keypair server.example.com -m 12    # самоподписанный сертификат ECDSA P-256
```

## Связанные разделы

- [Обзор схемы конфигурации](../02-config/schema-overview.md)
- [Входящие подключения (Inbounds)](../02-config/inbounds/README.md)
- [Исходящие подключения (Outbounds)](../02-config/outbounds/README.md)
- [Туннельные эндпоинты (Endpoints)](../02-config/endpoints.md)
- [Справочник CLI и параметров рантайма](../04-api-and-cli/cli-and-runtime.md)
