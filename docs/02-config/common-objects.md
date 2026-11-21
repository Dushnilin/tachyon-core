# Переиспользуемые объекты конфигурации

Различные секции `tachyon-core` (`inbounds`, `outbounds`, `endpoints`, `dns.servers`, `ntp`, `http_clients`) встраивают общие наборы параметров. Ниже приведена полная спецификация каждого переиспользуемого объекта.

---

## Объект `listen` (параметры прослушивания)

Встраивается непосредственно (на верхний уровень объекта, без отдельной обёртки) во все сетевые входящие подключения (`mixed`, `http`, `socks`, `tproxy`, `redirect`, `direct`, `vless`, `vmess`, `trojan`, `shadowsocks`, `shadowtls`, `anytls`, `naive`, `hysteria`, `hysteria2`, `tuic`, `snell`, `mieru`, `mtproto`, `trusttunnel`, `openconnect`, `masque`, `fptn`, `tewfai`, `wdtt`).

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `listen` | `IP` | — | Локальный IPv4 или IPv6 адрес прослушивания (например, `"127.0.0.1"`, `"0.0.0.0"`, `"::"` или `"[::1]"`). |
| `listen_port` | `uint16` | `0` | Порт прослушивания (`0..65535`). При `0` ОС выделяет эфемерный порт. |
| `ipv6_only` | `bool` | `false` | Для IPv6-сокета включает `IPV6_V6ONLY` (запрещает приём IPv4-mapped соединений на `::`). |
| `bind_interface` | `string` | — | Имя сетевого интерфейса для привязки слушающего сокета. |
| `routing_mark` | `FwMark` | — | Метка маршрутизации Linux (`SO_MARK`, `uint32` или строка с базовым префиксом `0x`/`0o`/`0b`). |
| `reuse_addr` | `bool` | `false` | Устанавливает `SO_REUSEADDR` / `SO_REUSEPORT` при привязке порта. |
| `netns` | `string` | — | Тег, имя или путь сетевого пространства имён Linux (из `network_namespaces`). |
| `disable_tcp_keep_alive` | `bool` | `false` | Отключает TCP keep-alive на принимаемых соединениях. |
| `tcp_keep_alive` | `Duration` | — | Время простоя до первого keep-alive зонда. |
| `tcp_keep_alive_interval` | `Duration` | — | Интервал между повторными keep-alive зондами. |
| `tcp_fast_open` | `bool` | `false` | Включает TCP Fast Open (`TCP_FASTOPEN`) на слушающем сокете. |
| `tcp_multi_path` | `bool` | `false` | Включает Multipath TCP (`TCP_MPTCP_ENABLED`, только Linux/Android). |
| `udp_fragment` | `bool` | `false` | Разрешает фрагментацию исходящих UDP-пакетов (при `false` выставляется запрет фрагментации). |
| `udp_timeout` | `Duration \| number` | `"2m"` (`120s`) | Таймаут неактивности UDP-сессии (строка `Duration` или число секунд; на устройствах с ограниченной ОЗУ может адаптироваться автоматически). |
| `detour` | `string` | — | Перенаправляет трафик входящего подключения напрямую в указанный тег другого входящего/исходящего обработчика. |
| `proxy_protocol` | `bool` | `false` | Включает разбор заголовка HAProxy PROXY Protocol v1/v2 перед протоколом уровня приложения. |
| `proxy_protocol_accept_no_header` | `bool` | `false` | При `proxy_protocol: true` разрешает принимать соединения без PROXY-заголовка. |
| `fullcone` | `bool` | `false` | Включает режим FullCone NAT (Endpoint-Independent Mapping & Filtering) для UDP на данном inbound. |
| `udp_nat_mode` | `string` | `"default"` | Режим UDP NAT: `"fullcone"`, `"full_cone"`, `"full-cone"`, `"eim_eif"`, `"endpoint_independent"`, `"symmetric"`, `"default"`. |
| `udp_fullcone_max_bindings` | `int` | `4096` | Лимит одновременных FullCone UDP-привязок (`64..=65536`). |
| `filter` | `Listable<CIDR> \| object` | — | Фильтр клиентских исходных IP/CIDR. Допускает: список IP/CIDR с опциональным префиксом инверсии `!` (например, `["192.168.0.0/16", "!192.168.1.50/32"]`) или объект `{"allow" / "include": Listable<CIDR>, "deny" / "exclude": Listable<CIDR>}` (пары `allow`/`include` и `deny`/`exclude` не должны конфликтовать). |
| `ips_excluded`, `ipsExcluded` | `Listable<string>` | — | Исключения IP/CIDR из инспекции протокола (`sniff`): IP, CIDR, `"private"`, `"geoip:<код>"`, `"ext:<значение>"` (поддерживается префикс `!`; оба написания не должны конфликтовать). |
| `domains_excluded`, `domainsExcluded` | `Listable<string>` | — | Домены, для которых инспекция протокола не переопределяет адрес назначения (оба написания не должны конфликтовать). |

### Устаревшие и удалённые поля `listen`

Следующие поля сохранены в списке известных ключей исключительно для выдачи явной ошибки миграции — любое ненулевое значение (`true`, непустая строка, ненулевая длительность) отклоняется валидатором с ошибкой `legacy inbound fields are deprecated and removed in tachyon-core, use route rule actions instead`:

- `sniff` — используйте правило маршрутизации с `"action": "sniff"`.
- `sniff_override_destination` — поведение включено в действие `"action": "sniff"`.
- `sniff_timeout` — задаётся полем `timeout` в правиле `"action": "sniff"`.
- `domain_strategy` — задаётся полем `strategy` в правиле `"action": "resolve"`.
- `udp_disable_domain_unmapping` — задаётся в правиле `"action": "route"` или `"action": "route-options"`.

---

## Объект `dialer` (параметры исходящего подключения)

Встраивается напрямую в объекты `outbounds[]`, `endpoints[]`, `dns.servers[]`, `ntp`, `http_clients[]` и `cloudflared` (`control_dialer` / `tunnel_dialer`).

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `detour` | `string` | — | Тег другого outbound или endpoint, через который устанавливается соединение. При заданном `detour` отключается параллельный дозвон Happy Eyeballs. |
| `bind_interface` | `string` | — | Исходящий сетевой интерфейс (`SO_BINDTODEVICE` на Linux/Android, `IP_BOUND_IF` на macOS/iOS, `IP_UNICAST_IF` на Windows). |
| `inet4_bind_address` | `IP` | — | Локальный IPv4-адрес источника перед подключением. |
| `inet6_bind_address` | `IP` | — | Локальный IPv6-адрес источника (поддерживает зону `%iface` для link-local). |
| `bind_address_no_port` | `bool` | `false` | Устанавливает `IP_BIND_ADDRESS_NO_PORT` (только Linux/Android; на других ОС вызывает ошибку инициализации). |
| `protect_path` | `string` | — | Путь к Unix-сокету внешнего помощника для защиты файлового дескриптора от зацикливания VPN (только Unix). |
| `routing_mark` | `FwMark` | — | Метка исходящих пакетов `SO_MARK` (только Linux/Android; ненулевое значение на других ОС вызывает ошибку). |
| `reuse_addr` | `bool` | `false` | Устанавливает `SO_REUSEADDR` на исходящем сокете. |
| `netns` | `string` | — | Сетевое пространство имён Linux (тег из `network_namespaces`, имя или путь). Вне Linux игнорируется с предупреждением. |
| `connect_timeout` | `Duration` | `"5s"` | Таймаут установления TCP-соединения. |
| `tcp_fast_open` | `bool` | `false` | Включает TCP Fast Open на исходящем соединении (отключает параллельный дозвон Happy Eyeballs). |
| `tcp_multi_path` | `bool` | `false` | Включает Multipath TCP (`TCP_MPTCP_ENABLED`, только Linux/Android). |
| `disable_tcp_keep_alive` | `bool` | `false` | Отключает TCP keep-alive на исходящем сокете. |
| `tcp_keep_alive` | `Duration` | `"30s"` | Интервал простоя до первого keep-alive зонда. |
| `tcp_keep_alive_interval` | `Duration` | `"15s"` | Интервал между повторными keep-alive зондами. |
| `udp_fragment` | `bool` | `false` | При `false` устанавливает запрет IP-фрагментации UDP (`IP_PMTUDISC_DONT` / DF); при `true` разрешает фрагментацию. |
| `domain_resolver` | `string \| object` | — | DNS-сервер для разрешения адреса `server` данного outbound. Либо тег DNS-сервера (`"dns-direct"`), либо объект `{"server": "<тег>", "strategy": "<стратегия>", "timeout": "<Duration>"}`. Обязателен на каждом outbound (кроме `block`), если в `dns.servers` >= 2 серверов и не задан `route.default_domain_resolver`. |
| `domain_strategy` | `string` | `""` | Стратегия разрешения доменного имени сервера: `""`, `"as_is"`, `"prefer_ipv4"`, `"prefer_ipv6"`, `"ipv4_only"`, `"ipv6_only"`. |
| `fallback_delay` | `Duration` | `"300ms"` | Задержка перед запуском второй попытки другого семейства IP (RFC 6555 Happy Eyeballs). |
| `network_strategy` | `string` | `""` | Стратегия выбора интерфейсов: `""`, `"default"`, `"hybrid"`, `"fallback"`. Конфликтует с `bind_interface`, `inet4_bind_address`, `inet6_bind_address` и `tcp_fast_open`. В текущей сборке валидируется, но во время выполнения игнорируется с предупреждением. |
| `network_type` | `Listable<string>` | — | Допустимые типы интерфейсов: `"wifi"`, `"cellular"`, `"ethernet"`, `"other"`. Принимается валидатором, игнорируется во время выполнения с предупреждением. |
| `fallback_network_type` | `Listable<string>` | — | Резервные типы интерфейсов (`"wifi"`, `"cellular"`, `"ethernet"`, `"other"`). Игнорируется во время выполнения с предупреждением. |
| `tcp_profile` | `string` | `""` (`"none"`) | Выравнивание L3/L4-параметров TCP (`IP_TTL`, `TCP_MAXSEG`, `SO_RCVBUF`) под стек выбранной ОС: `"auto"` (выбирается по `tls.utls.fingerprint`), `"windows"` (`win`, `win11`: TTL 128, MSS 1460, RCVBUF 65535), `"macos"` (`darwin`, `mac`: TTL 64, MSS 1460, RCVBUF 131072), `"ios"` (`iphone`: TTL 64, MSS 1460, RCVBUF 65535), `"android"` (TTL 64, MSS 1460, RCVBUF 65535), `"linux"` (TTL 64, MSS 1460, RCVBUF 87380), `"none"`. |
| `ip_ttl` | `int` | — | Явное переопределение IPv4 `IP_TTL` / IPv6 `IPV6_UNICAST_HOPS` (`1..=255`). Перекрывает `tcp_profile`. |
| `tcp_mss` | `int` | — | Явное переопределение `TCP_MAXSEG` (`536..=65535`). Перекрывает `tcp_profile`. |
| `tcp_rcvbuf` | `int` | — | Явное переопределение начального `SO_RCVBUF` (`4096..=16777216` байт). Перекрывает `tcp_profile`. |
| `preconnect` | `any` | — | Параметры предварительного установления TCP-соединений (разрешено схемой `dialer`). |
| `warm_pool` | `any` | — | Параметры прогретого пула соединений (разрешено схемой `dialer`). |
| `fragment`, `tcp_fragment` | `bool \| object` | `false` | TCP-фрагментация начальных сегментов (см. таблицу ниже). |
| `finalmask` | `object` | — | Пайплайн постобработки пакетов (`tcp`, `udp`, `quicParams` / `quic_params`, см. ниже). |

### Параметры `fragment` / `tcp_fragment` в `dialer`

Принимает `bool` (при `true` включается фрагментация со значениями по умолчанию: длины `10-50` байт, задержки `1-10` мс) или объект:

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `true` (для объекта) | Включает фрагментацию. |
| `packets` | `int \| string` | — | Какие пакеты фрагментировать: `"tlshello"` / `"tls_hello"` (только TLS ClientHello), целое `>= 1` или диапазон `"1-3"` / `[1, 3]`. |
| `lengths`, `length` | `int \| string \| [int, int]` | `"10-50"` | Размер фрагмента в байтах (`>= 1`, число или диапазон `"min-max"`). |
| `delays`, `delay`, `interval` | `int \| Duration \| string` | `"1-10"` | Пауза между фрагментами (миллисекунды, `Duration` или диапазон `"5ms-15ms"` / `"5-15"`). |
| `max_split`, `maxSplit` | `int \| string \| [int, int]` | — | Максимальное число разбиений (`>= 0`). |

### Параметры `finalmask` в `dialer`

| Поле | Тип | Описание |
|---|---|---|
| `tcp` | `object \| array<object>` | Список стадий TCP-обработки. Для `type: "fragment"` / `"tcp_fragment"` параметры `packets`, `lengths`, `delays`, `max_split` могут находиться в объекте `settings` или напрямую в элементе. |
| `udp` | `object \| array<object>` | Список стадий UDP-обработки (например, `type: "udpHop"` / `"udp_hop"` с `settings.ports` и `settings.interval`, либо обфускация QUIC-уровня для Hysteria2). |
| `quicParams`, `quic_params` | `object` | Дополнительные параметры QUIC-уровня. |

### Пример `dialer` (в составе outbound)

```json
{
  "type": "vless",
  "tag": "proxy-out",
  "server": "edge.example.com",
  "server_port": 443,
  "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
  "bind_interface": "eth0",
  "connect_timeout": "5s",
  "tcp_fast_open": false,
  "tcp_profile": "auto",
  "domain_resolver": {
    "server": "dns-direct",
    "strategy": "prefer_ipv4"
  },
  "fragment": {
    "packets": "tlshello",
    "lengths": "10-20",
    "delays": "5-15",
    "max_split": 4
  }
}
```

---

## Объект `tls` (клиент)

Используется в исходящих подключениях (`vless`, `vmess`, `trojan`, `http`, `anytls`, `shadowtls`, `naive`, `hysteria`, `hysteria2`, `tuic`, `masque`, `fptn`, `tewfai`, `trusttunnel`), DNS-серверах (`tls`, `https`, `quic`, `h3`) и `http_clients`. Для `hysteria`, `hysteria2`, `tuic`, `anytls`, `naive` и `shadowtls` включение TLS (`"enabled": true`) обязательно.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает TLS. Для DNS-серверов типов `tls`, `https`, `quic`, `h3` выставляется в `true` автоматически при отсутствии поля. |
| `engine` | `string` | `""` | Выбор TLS-движка: `""` / `"go"` (встроенный pure-Rust стек), `"apple"` (только macOS/iOS), `"windows"` (только Windows). |
| `disable_sni` | `bool` | `false` | Не отправлять расширение SNI в ClientHello. Запрещено в сочетании с REALITY при `insecure: false`. |
| `server_name` | `string` | значение `server` | Имя хоста для SNI и проверки сертификата. Если не задано (и `server` пуст), требуется `insecure: true`. |
| `insecure` | `bool` | `false` | Отключает проверку цепочки и имени сертификата сервера. |
| `alpn` | `Listable<string>` | зависит от протокола | Список протоколов ALPN (например, `["h2", "http/1.1"]`). |
| `min_version` | `string` | `"1.2"` | Минимальная версия TLS. Валидатор допускает `"1.0"`, `"1.1"`, `"1.2"`, `"1.3"`; движок подключения поддерживает `"1.2"` и `"1.3"`. |
| `max_version` | `string` | `"1.3"` | Максимальная версия TLS (`"1.0"`, `"1.1"`, `"1.2"`, `"1.3"`; движок поддерживает `"1.2"` и `"1.3"`). |
| `cipher_suites` | `Listable<string>` | встроенный набор | Список допустимых шифронаборов (см. перечень ниже). |
| `curve_preferences` | `Listable<string>` | — | Предпочитаемые группы обмена ключами (без учёта регистра): `"p256"`, `"p384"`, `"p521"`, `"x25519"`, `"x25519mlkem768"`. |
| `certificate` | `Listable<string>` | — | Встроенный корневой PEM-сертификат (конфликтует с `certificate_public_key_sha256`). |
| `certificate_path` | `string` | — | Путь к PEM-файлу корневого сертификата (конфликтует с `certificate_public_key_sha256`). |
| `certificate_public_key_sha256` | `Listable<bytes>` | — | Закрепление SPKI (SHA-256 публичного ключа сертификата): base64-строка, 64-символьный hex (допускаются префиксы `sha256:` / `sha256/` / `pin-sha256:` / `pin-sha256=`) либо массив байт. |
| `certificate_sha256` | `Listable<string>` | — | Закрепление SHA-256 от DER-сертификата конечного узла (hex или base64). |
| `client_certificate` | `Listable<string>` | — | Встроенный клиентский PEM-сертификат для mTLS (должен задаваться совместно с `client_key` / `client_key_path`). |
| `client_certificate_path` | `string` | — | Путь к клиентскому PEM-сертификату для mTLS. |
| `client_key` | `Listable<string>` | — | Встроенный приватный ключ клиента для mTLS. |
| `client_key_path` | `string` | — | Путь к файлу приватного ключа клиента для mTLS. |
| `fragment` | `bool` | `false` | Включает фрагментацию TLS ClientHello на несколько TCP-сегментов. |
| `fragment_fallback_delay` | `Duration` | — | Задержка отката при фрагментации. |
| `record_fragment` | `bool` | `false` | Включает разбиение TLS ClientHello на несколько TLS-записей. |
| `spoof` | `string` | — | Доменное имя для подмены (должно отличаться от `server_name`; требует TLS ClientHello с не-IP SNI). |
| `spoof_method` | `string` | `""` | Метод отправки вспомогательного пакета (требует `spoof`): `"wrong-sequence"`, `"wrong-checksum"`, `"wrong-ack"`, `"wrong-md5"`, `"wrong-timestamp"`. |
| `kernel_tx` | `bool` | `false` | Разгрузка передачи TLS в ядро Linux (kTLS). Вне Linux вызывает ошибку валидации. |
| `kernel_rx` | `bool` | `false` | Разгрузка приёма TLS в ядро Linux (kTLS). Вне Linux вызывает ошибку валидации. |
| `handshake_timeout` | `Duration` | — | Таймаут TLS-рукопожатия. |
| `verify_peer_cert_by_name` | `Listable<string>` | — | Дополнительные допустимые имена для проверки сертификата (поддерживает специальное значение `"fromMitm"`). |
| `verify_peer_cert_in_names` | `Listable<string>` | — | Альтернативное написание списка проверяемых имён сертификата. |
| `utls` | `object` | — | Профиль отпечатка TLS ClientHello (см. ниже). Обязателен при использовании `reality`. |
| `reality` | `object` | — | Параметры клиента REALITY (см. ниже). Конфликтует с `ech`. |
| `ech` | `object` | — | Параметры Encrypted Client Hello (RFC 9849, см. ниже). |

Допустимые значения `cipher_suites`:
- `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`, `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`, `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`, `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`

### `tls.utls`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает имитацию отпечатка ClientHello. На QUIC-протоколах (`hysteria`, `hysteria2`, `tuic`, `xhttp` с ALPN `h3`) uTLS не применяется и игнорируется с предупреждением. |
| `fingerprint` | `string` | `"chrome"` | Идентификатор профиля ClientHello. |

Поддерживаемые значения `tls.utls.fingerprint`:

| Группа | Значения | Поведение |
|---|---|---|
| Chrome (базовый и варианты) | `chrome`, `chrome_psk`, `chrome_pq`, `chrome_pq_psk` | Актуальный шаблон Chrome (включая GREASE и гибридный key share `X25519MLKEM768`). |
| Chrome с перемешиванием расширений | `chrome_psk_shuffle`, `chrome_padding_psk_shuffle` | Шаблон Chrome со случайной перестановкой внутренних расширений (сохраняя граничные слоты GREASE). |
| Другие браузеры и мобильные ОС | `firefox`, `safari`, `edge`, `ios`, `android`, `360`, `qq` | Захваченные профили ClientHello соответствующих клиентов. |
| Случайные профили | `random`, `randomized` | `random` выбирает один профиль из встроенного пула на время работы; `randomized` генерирует случайную перестановку расширений и шифров на базе TLS 1.3. |

Также принимаются и автоматически нормализуются версионированные имена в стиле Go/Xray (`hellochrome_120`, `hellofirefox_120`, `hellosafari_16_0`, `helloandroid_11_okhttp`, `randomizedalpn`, `randomizednoalpn`).

### `tls.reality` (клиент)

Требует `"utls": { "enabled": true }` и несовместим с `"ech": { "enabled": true }`.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает REALITY на клиенте. |
| `public_key` | `string` | *(обязательно)* | 32-байтный публичный ключ X25519 сервера в формате raw URL-safe base64 (без `=`). |
| `short_id` | `string` | `""` | Шестнадцатеричный идентификатор (чётной длины, от 0 до 16 hex-символов, т. е. 0..8 байт). |
| `key_share` | `string` | `""` | Режим обмена ключами: `""` (по умолчанию), `"hybrid"` или `"classical"`. |
| `support_x25519mlkem768`, `support-x25519mlkem768` | `bool` | `true` | Предлагает постквантовый гибридный обмен ключами `X25519MLKEM768` в ClientHello, даже если базовый браузерный профиль его не содержит. |
| `spider_x`, `spiderX` | `string` | `""` | Поле совместимости клиентских профилей (принимается валидатором). |

### `tls.ech` (клиент)

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает Encrypted Client Hello (RFC 9849). |
| `config` | `Listable<string>` | — | Встроенный ECHConfigList (base64 или PEM `-----BEGIN ECH CONFIGS-----`), либо DNS URI для автоматического получения HTTPS-записи (`https://...`, `udp://...`, `tcp://...`, `tls://...`, `quic://...`, `h3://...`, `domain+https://...` и др.). |
| `config_path` | `string` | — | Путь к локальному файлу с ECHConfigList (PEM, base64 или бинарный wire-формат). |
| `query_server_name` | `string \| bool` | — | Доменное имя для запроса DNS-записи `HTTPS` (TYPE65) или спецификация `domain+<dns-uri>`. |
| `outer_sni`, `public_name` | `string` | — | Явное переопределение внешнего открытого SNI (Outer ClientHello). |
| `auto_dns` | `bool` | `true` (если `config` пуст или задан DNS URI) | Разрешает автоматическое получение ECHConfigList через DNS. |
| `grease_fallback` | `bool` | `true` | Отправляет ECH GREASE при отсутствии актуальной конфигурации ECH. |
| `pq_signature_schemes_enabled` | `bool` | `false` | Поле совместимости схемы (валидируется как `bool`). |
| `dynamic_record_sizing_disabled` | `bool` | `false` | Поле совместимости схемы (валидируется как `bool`). |

---

## Объект `tls` (сервер)

Используется на серверных `inbounds[]` (`mixed`, `http`, `vless`, `vmess`, `trojan`, `shadowsocks`, `anytls`, `naive`, `hysteria`, `hysteria2`, `tuic`, `masque`, `fptn`, `tewfai`, `trusttunnel`, `openconnect`). Для `hysteria`, `hysteria2`, `tuic`, `naive` включение TLS обязательно.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает серверный TLS. |
| `server_name` | `string` | — | Имя сервера (для сопоставления SNI). |
| `insecure` | `bool` | `false` | Допускает отсутствие сертификата при `check` (эпемерный сертификат); во время `run` сервер требует явный сертификат/ключ либо `reality`. Конфликтует с `acme` и `certificate_provider`. |
| `alpn` | `Listable<string>` | зависит от транспорта | Поддерживаемые ALPN. Автоматически дополняется для `grpc`/`http`/`naive` (`h2`) и `xhttp` (`h2`, `http/1.1`). |
| `min_version` | `string` | `"1.2"` | Минимальная версия TLS. |
| `max_version` | `string` | `"1.3"` | Максимальная версия TLS. |
| `cipher_suites` | `Listable<string>` | встроенный набор | Список разрешённых шифронаборов. |
| `curve_preferences` | `Listable<string>` | — | Предпочитаемые эллиптические кривые и PQ-группы. |
| `certificate` | `Listable<string>` | — | Встроенная цепочка сертификатов в формате PEM. |
| `certificate_path` | `string` | — | Путь к файлу PEM-сертификата. |
| `key` | `Listable<string>` | — | Встроенный приватный ключ в формате PEM. |
| `key_path` | `string` | — | Путь к файлу приватного ключа PEM. |
| `client_authentication` | `string` | — | Режим проверки клиентских сертификатов (mTLS). |
| `client_certificate` | `Listable<string>` | — | Встроенные доверенные клиентские CA-сертификаты (PEM). |
| `client_certificate_path` | `string` | — | Путь к файлу доверенных клиентских CA-сертификатов. |
| `client_certificate_public_key_sha256` | `Listable<bytes>` | — | Закрепление SHA-256 публичных ключей клиентских сертификатов. |
| `kernel_tx` | `bool` | `false` | Включение kTLS на передачу (Linux). |
| `kernel_rx` | `bool` | `false` | Включение kTLS на приём (Linux). |
| `handshake_timeout` | `Duration` | `"10s"` | Таймаут завершения TLS-рукопожатия со стороны клиента. |
| `reality` | `object` | — | Серверная конфигурация REALITY (см. ниже). Взаимоисключающа с `acme` и `certificate_provider`. |
| `ech` | `object` | — | Серверные параметры ECH (поле схемы). |
| `acme` | `object` | — | Встроенная конфигурация ACME (`domain` и др.). Принимается схемой валидации, но на этапе `run` отклоняется (`acme is not supported by this server yet`); используйте внешнее обновление сертификатов + `certificate_path`/`key_path`. |
| `certificate_provider` | `string \| object` | — | Внешний или встроенный провайдер сертификатов (`type: "acme"` с `domain`, `data_directory`, `default_server_name`, `email`, `provider`, `account_key`, `disable_http_challenge`, `disable_tls_alpn_challenge`, `alternative_http_port`, `alternative_tls_port`, `external_account`, `dns01_challenge`, `http_challenge`, `challenges`; либо `type: "tailscale"` с `endpoint`). В текущей сборке валидируется по схеме, но не поддерживается при старте сервера. |

### `tls.reality` (сервер)

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает серверный режим REALITY (не требует сертификата и ключа). |
| `handshake` | `object` | *(обязательно)* | Целевой маскировочный узел: `{"server": "<домен>", "server_port": 443}` (и опциональные поля `dialer`). |
| `private_key` | `string` | *(обязательно)* | 32-байтный приватный ключ X25519 в формате raw URL-safe base64. |
| `short_id` | `Listable<string>` | `[]` | Один или несколько допустимых hex `short_id` (0..16 символов; пустая строка разрешает клиентов без `short_id`). |
| `max_time_difference` | `Duration \| int` | `"600s"` | Максимально допустимое расхождение системных часов клиента и сервера. |

### Пример `tls` (клиент REALITY + uTLS и сервер REALITY)

```json
{
  "client_tls_example": {
    "enabled": true,
    "server_name": "www.example.com",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    },
    "reality": {
      "enabled": true,
      "public_key": "1234567890abcdef1234567890abcdef1234567890A",
      "short_id": "0123456789abcdef",
      "support_x25519mlkem768": true
    }
  },
  "server_tls_example": {
    "enabled": true,
    "server_name": "www.example.com",
    "reality": {
      "enabled": true,
      "handshake": {
        "server": "www.example.com",
        "server_port": 443
      },
      "private_key": "1234567890abcdef1234567890abcdef1234567890B",
      "short_id": ["0123456789abcdef"],
      "max_time_difference": "1m"
    }
  }
}
```

---

## Объект `transport` (V2Ray-транспорты)

Используется в `vless`, `vmess`, `trojan` (клиент и сервер). Допустимые типы поля `type`: `"http"`, `"ws"`, `"quic"`, `"grpc"`, `"httpupgrade"`, `"xhttp"`. На серверных `inbounds[]` обслуживаются `ws`, `httpupgrade`, `grpc`, `xhttp` и `http` (`h2`); серверный V2Ray `quic` на inbound не поддерживается и отклоняется при проверке.

### `type: "http"`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"http"` | Тип транспорта. |
| `host` | `Listable<string>` | — | Заголовок `Host` (одно имя или список). |
| `path` | `string` | `"/"` | Путь HTTP-запроса. |
| `method` | `string` | `"PUT"` | HTTP-метод. |
| `headers` | `object` | `{}` | Дополнительные HTTP-заголовки (`{"Name": "Value" | ["V1", "V2"]}`). |
| `idle_timeout` | `Duration` | — | Таймаут простоя HTTP/2-соединения. |
| `ping_timeout` | `Duration` | — | Таймаут ожидания ответа на HTTP/2 PING. |

### `type: "ws"` (WebSocket)

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"ws"` | Тип транспорта. |
| `path` | `string` | `"/"` | Путь WebSocket-подключения. |
| `headers` | `object` | `{}` | Дополнительные HTTP-заголовки рукопожатия (например, `Host`). |
| `max_early_data` | `uint32` | `0` | Максимальный объём ранних данных (0-RTT), передаваемых в заголовке рукопожатия. |
| `early_data_header_name` | `string` | `""` | Имя HTTP-заголовка для ранних данных (например, `"Sec-WebSocket-Protocol"`). |

### `type: "quic"`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"quic"` | Тип транспорта (дополнительных полей нет). Поддерживается только на outbound. |

### `type: "grpc"`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"grpc"` | Тип транспорта. |
| `service_name` | `string` | `"TunService"` | Имя gRPC-сервиса (путь `/<service_name>/Tun`). |
| `idle_timeout` | `Duration` | — | Период простоя до отправки HTTP/2 PING. |
| `ping_timeout` | `Duration` | — | Таймаут ответа на PING. |
| `permit_without_stream` | `bool` | `false` | Разрешает отправку PING при отсутствии активных потоков. |

### `type: "httpupgrade"`

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"httpupgrade"` | Тип транспорта. |
| `host` | `string` | — | Значение заголовка `Host`. |
| `path` | `string` | `"/"` | Путь запроса `Upgrade`. |
| `headers` | `object` | `{}` | Дополнительные HTTP-заголовки. |

### `type: "xhttp"` (SplitHTTP / XHTTP)

Поддерживает как плоскую запись параметров (snake_case и псевдонимы `session_id_*`, `h2Params`, `scStreamUpServerSecs`, `uplinkHTTPMethod`), так и вложенный блок `extra` (объект или JSON-строка, совместимая с профилями Xray-core).

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `type` | `string` | `"xhttp"` | Тип транспорта. |
| `host` | `string` | — | Заголовок `Host`. |
| `path` | `string` | `"/"` | Базовый путь запросов. |
| `mode` | `string` | `"auto"` | Режим передачи: `""`, `"auto"`, `"packet-up"`, `"stream-up"`, `"stream-one"`. |
| `headers` | `object` | `{}` | Дополнительные HTTP-заголовки. |
| `extra` | `object \| string` | — | Дополнительные настройки XHTTP (в т. ч. camelCase-поля Xray-core), разворачиваются в канонические поля до валидации. |
| `x_padding_bytes` | `int \| string` | `"100-1000"` | Размер случайного заполнения в байтах (`"N"` или `"min-max"`, `>= 0`). |
| `x_padding_obfs_mode` | `bool` | `false` | Включает расширенное размещение заполнения (`x_padding_placement`, `x_padding_key`, `x_padding_header`, `x_padding_method`). |
| `x_padding_placement` | `string` | — | Место размещения заполнения: `"cookie"`, `"header"`, `"query"`, `"queryInHeader"`. |
| `x_padding_key` | `string` | — | Имя параметра/cookie для заполнения. |
| `x_padding_header` | `string` | — | Имя HTTP-заголовка для заполнения. |
| `x_padding_method` | `string` | — | Способ генерации заполнения: `"repeat-x"`, `"tokenish"`. |
| `no_grpc_header` | `bool` | `false` | Отключает gRPC-подобный `Content-Type` в потоковых запросах. |
| `no_sse_header` | `bool` | `false` | Отключает заголовок `text/event-stream` на стороне сервера. |
| `session_placement` (`session_id_placement`) | `string` | `"path"` | Размещение идентификатора сессии: `"path"`, `"query"`, `"header"`, `"cookie"`. |
| `session_key` (`session_id_key`) | `string` | — | Имя ключа для идентификатора сессии. |
| `session_table` (`session_id_table`) | `string` | `"hex"` (если задан `session_length`) | Алфавит генерации `session_id`: `"ALPHABET"`, `"Alphabet"`, `"BASE36"`, `"Base62"`, `"HEX"`, `"alphabet"`, `"base36"`, `"hex"`, `"number"` либо произвольная строка символов. |
| `session_length` (`session_id_length`) | `int \| string` | — | Длина `session_id` (`"N"` или `"min-max"`, `> 0`). Пространство идентификаторов `sum(radix^n)` должно быть не меньше `2^24` (16 777 216). |
| `seq_placement` | `string` | `"path"` | Размещение порядкового номера пакета: `"path"`, `"query"`, `"header"`, `"cookie"`. |
| `seq_key` | `string` | — | Имя ключа для порядкового номера. |
| `uplink_data_placement` | `string` | `"body"` | Размещение исходящей полезной нагрузки: `"body"`, `"auto"`, `"header"`, `"cookie"`. Значения `"header"` и `"cookie"` допустимы **только** при `mode: "packet-up"`. |
| `uplink_data_key` | `string` | — | Имя ключа для исходящих данных в заголовке/cookie. |
| `uplink_chunk_size` | `int \| string` | — | Размер чанка исходящего потока (`"N"` или `"min-max"`, `>= 0`). |
| `uplink_http_method` (`uplinkHTTPMethod`) | `string` | `"POST"` | HTTP-метод для uplink-запросов: `"GET"`, `"HEAD"`, `"POST"`, `"PUT"`, `"PATCH"`, `"OPTIONS"`, `"DELETE"`. |
| `sc_max_each_post_bytes` | `int \| string` | — | Максимальный размер одного POST-запроса в `packet-up` (`>= 0`). |
| `sc_min_posts_interval_ms` | `int \| string` | — | Минимальный интервал между POST-запросами в миллисекундах (`>= 0`). |
| `sc_max_concurrent_posts` | `int` | — | Максимум одновременных POST-запросов. |
| `sc_max_buffered_posts` | `int` | — | Максимум буферизуемых POST-запросов на сервере. |
| `sc_stream_up_server_secs` (`scStreamUpServerSecs`) | `int \| string` | — | Время жизни серверного uplink-потока в секундах (`>= -1`, `-1` отключает ограничение). |
| `server_max_header_bytes` | `int` | — | Максимальный размер заголовков на сервере XHTTP. |
| `xmux` | `object` | — | Настройки пула соединений XHTTP (см. таблицу ниже). |
| `h2_params` (`h2Params`) | `object` | — | Тонкая настройка HTTP/2: целочисленные (`initial_window_size`, `initial_connection_window_size`, `conn_window_size`, `max_frame_size`, `max_concurrent_streams`, `max_send_buffer_size`, `max_header_list_size`, `max_receive_buffer_per_stream`, `max_receive_buffer_per_connection`, `max_upload_buffer_per_stream`, `max_upload_buffer_per_connection`, `max_decoder_header_table_size`, `max_encoder_header_table_size`), длительности/мс (`idle_timeout`, `keep_alive_interval`, `keep_alive_timeout`, `ping_timeout`, `send_ping_timeout`, `read_idle_timeout`, `write_byte_timeout`, `new_stream_timeout`) и флаги (`allow_http`, `disable_compression`, `strict_max_concurrent_streams`, `permit_prohibited_cipher_suites`; допускаются также camelCase/PascalCase варианты). |

#### Поля `transport.xmux` (для `xhttp`)

Поля диапазона принимают целое число, строку `"min-max"`, массив `[min, max]` или объект `{"from": min, "to": max}`. `max_concurrency` и `max_connections` взаимоисключающи.

| Поле | Тип | Описание |
|---|---|---|
| `max_concurrency` | `range` | Максимум одновременных потоков на одно соединение (взаимоисключающе с `max_connections`). |
| `max_connections` | `range` | Максимум одновременных соединений (взаимоисключающе с `max_concurrency`). |
| `c_max_reuse_times` | `range` | Максимум повторных использований одного соединения. |
| `h_max_request_times` | `range` | Максимум HTTP-запросов на одно соединение. |
| `h_max_reusable_secs` | `range` | Максимальное время жизни переиспользуемого соединения в секундах. |
| `h_keep_alive_period` | `int` | Период keep-alive в секундах. |

### Пример `transport` (`xhttp`)

```json
{
  "transport": {
    "type": "xhttp",
    "host": "cdn.example.com",
    "path": "/assets",
    "mode": "stream-up",
    "x_padding_bytes": "100-1000",
    "xmux": {
      "max_concurrency": "16-32",
      "h_max_request_times": "600-900",
      "h_max_reusable_secs": "1800-3000"
    },
    "h2_params": {
      "initial_window_size": 65536,
      "initial_connection_window_size": 1048576,
      "keep_alive_interval": "15s"
    }
  }
}
```

---

## Объект `multiplex` (мультиплексирование)

Используется в `vless`, `vmess`, `trojan`, `shadowsocks` (исходящие и входящие подключения). Реализует протокол `sing-mux` (`sp.mux.sing-box.arpa:444`).

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает мультиплексирование. |
| `protocol` | `string` | `"h2mux"` | Протокол мультиплексирования. Валидатор на outbound допускает `"h2mux"`, `"smux"`, `"yamux"`, однако во время выполнения реализован только `"h2mux"` (по умолчанию). На серверных `inbounds[]` допускается только `"h2mux"` (или пустое значение). |
| `max_connections` | `int` | `0` (адаптивно: `4` при ОЗУ < 128 MiB, `8` при >= 128 MiB) | Максимальное число базовых транспортных соединений в пуле (только outbound). |
| `min_streams` | `int` | `0` | Минимальное число потоков в соединении перед открытием нового (только outbound). |
| `max_streams` | `int` | `0` | Максимальное число потоков в одном соединении (только outbound). |
| `padding` | `bool` | `false` | Включает выравнивание (padding) первых 16 кадров сессии `sing-mux` (v1). |
| `brutal` | `object` | — | Параметры управления перегрузкой Brutal: `{"enabled": bool, "up_mbps": int, "down_mbps": int}`. |
| `smart_queue` | `bool` | `false` | Включает приоритизацию интерактивных потоков поверх фоновых загрузок внутри мультиплексора (только outbound). |
| `bulk_threshold_bytes` | `uint64` | — | Порог объёма передачи в байтах (`>= 1024`), после которого поток классифицируется как фоновый (`bulk`) при `smart_queue: true` (только outbound). |

### Пример `multiplex`

```json
{
  "multiplex": {
    "enabled": true,
    "protocol": "h2mux",
    "max_connections": 4,
    "min_streams": 4,
    "padding": true,
    "smart_queue": true,
    "bulk_threshold_bytes": 262144,
    "brutal": {
      "enabled": false,
      "up_mbps": 100,
      "down_mbps": 100
    }
  }
}
```

---

## Объект `udp_over_tcp` (UoT)

Используется в исходящих подключениях `shadowsocks`, `socks`, `naive` (а также поддерживается на серверах при приёме магических адресов UoT). Передаёт UDP-датаграммы инкапсулированными внутри TCP-потока.

Принимает либо `bool` (`true` эквивалентно `{"enabled": true, "version": 2}`), либо объект:

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | `bool` | `false` | Включает инкапсуляцию UDP-over-TCP. |
| `version` | `uint8` | `2` | Версия протокола UoT: `1` (legacy UoT v1) или `2` (UoT v2 с поддержкой connected/unconnected режима; `0` трактуется как `2`). Другие значения отклоняются при инициализации. |

### Пример `udp_over_tcp`

```json
{
  "udp_over_tcp": {
    "enabled": true,
    "version": 2
  }
}
```

---

## Объект `users` (учётные записи входящих подключений)

Массив `users` задаёт авторизованных пользователей на серверных `inbounds[]`. Поле `name` (когда присутствует) используется в логах и для сопоставления в правилах маршрутизации по полю `auth_user`. Набор полей элемента зависит от типа протокола:

| Протокол inbound | Поля элемента `users[]` | Примечание |
|---|---|---|
| `mixed`, `http`, `socks` | `username` (`string`), `password` (`string`) | Стандартная аутентификация HTTP Basic / SOCKS5. |
| `vless` | `name` (`string`), `uuid` (`string`, обязательно), `flow` (`string`, напр. `"xtls-rprx-vision"`) | Некорректная строка UUID преобразуется по UUIDv5 для совместимости. |
| `vmess` | `name` (`string`), `uuid` (`string`, обязательно), `alterId` (`int`, опционально, `0` для AEAD) | Обязателен хотя бы один пользователь. |
| `trojan` | `name` (`string`), `password` (`string`, обязательно) | Пароли пользователей должны быть уникальны в пределах одного inbound. |
| `shadowsocks` | `name` (`string`), `password` (`string`, обязательно) | В многопользовательском режиме Shadowsocks-2022 используется совместно с корневым серверным PSK `password`. |
| `hysteria2` | `name` (`string`), `password` (`string`, обязательно) | При включённой обфускации требуется непустой пароль хотя бы у одного пользователя. |
| `tuic` | `name` (`string`), `uuid` (`string`, обязательно), `password` (`string`) | `uuid` проверяется строго на формат UUID. |
| `anytls` | `name` / `username` (`string`), `password` (`string`, обязательно) | При пустом `users` может использоваться корневое поле `password`. |
| `naive` | `name` (`string`), `username` (`string`), `password` (`string`) | Используется HTTP Basic-авторизация; если `name` не задано, используется `username`. |
| `shadowtls` | `name` (`string`), `password` (`string`, обязательно) | Для ShadowTLS v3; в v2 может задаваться корневое `password`. |
| `snell` | `name` (`string`), `userkey` (`string`) | Поддерживается в Snell v6 (корневой `psk` имеет длину 12..255 байт). |
| `mieru` | `name` / `username` (`string`, обязательно), `password` (`string`, обязательно) | Оба поля обязательны и непусты. |
| `fptn` | `username` (`string`), `password` (`string`) | Учётные записи пользователей FPTN. |

### Пример `users` (VLESS)

```json
{
  "users": [
    {
      "name": "alice",
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
      "flow": "xtls-rprx-vision"
    }
  ]
}
```
