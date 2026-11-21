# Проводные спецификации протоколов и матрица совместимости

Документ фиксирует проводные (wire) форматы, поведенческие контракты, согласование ALPN и матрицу двусторонней совместимости всех прокси- и туннельных протоколов `tachyon-core` (v0.6.2) с внешними ядрами и панелями управления.

---

## 1. Сводная матрица поддержки протоколов

| Протокол | Outbound | Inbound | Секция конфига | TCP | UDP | ALPN по умолчанию | Транспорты / MUX / UoT |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **VLESS** | Да | Да | `outbounds` / `inbounds` | Да | Да (native / `xudp` / `packetaddr`) | По транспорту / TLS | `ws`, `httpupgrade`, `http`, `grpc`, `xhttp`, `h2mux` |
| **VMess** | Да | Да | `outbounds` / `inbounds` | Да | Да (native / `xudp` / `packetaddr`) | По транспорту / TLS | `ws`, `httpupgrade`, `http`, `grpc`, `xhttp`, `h2mux` |
| **Trojan** | Да | Да | `outbounds` / `inbounds` | Да | Да (native) | По транспорту / TLS | `ws`, `httpupgrade`, `http`, `grpc`, `xhttp`, `h2mux` |
| **Shadowsocks** | Да | Да | `outbounds` / `inbounds` | Да | Да (native + UoT v1/v2) | — (опц. TLS/plugin) | `h2mux`, UoT v1/v2, `obfs-local`/`v2ray-plugin` |
| **Hysteria (v1)** | Нет (только check) | Нет (только check) | `outbounds` / `inbounds` | — | — | — | Схема валидируется; runtime отклонён (используйте `hysteria2`) |
| **Hysteria2** | Да | Да | `outbounds` / `inbounds` | Да | Да (QUIC DATAGRAM) | `h3` | Salamander, Gecko/`finalmask`, port hopping, Brutal/BBR |
| **TUIC v5** | Да | Да | `outbounds` / `inbounds` | Да | Да (`native` / `quic` / UoT v2) | `h3` (или из `tls.alpn`) | EKM auth, 0-RTT, BBR/Cubic/Brutal |
| **AnyTLS** | Да | Да | `outbounds` / `inbounds` | Да | Да (UoT v2 поверх сессии) | По TLS | Встроенный session-mux + `padding_scheme` |
| **ShadowTLS v2/v3** | Да | Да | `outbounds` / `inbounds` | Да | Через вложенный `detour` | От целевого `handshake`-хоста | Маскировочный слой поверх TLS 1.3 |
| **NaiveProxy** | Да | Да | `outbounds` / `inbounds` | Да | Да (UoT v1/v2) | `h2` (TCP) / `h3` (QUIC) | HTTP/2 и HTTP/3 CONNECT + padding |
| **Snell v4 / v5 / v6** | Да (`v4–v6`) | Да (`v5–v6`) | `outbounds` / `inbounds` | Да | Да (native UDP forward) | — | HTTP/TLS `obfs`, пулинг `reuse`, v6 shaping |
| **Mieru v3** | Да | Да | `outbounds` / `inbounds` | Да | Да (TCP/UDP транспорт) | — | XChaCha20-Poly1305, `server_ports` |
| **FPTN** | Да | Да | `outbounds` / `inbounds` | Да | Да (через IP-стек `smoltcp`) | `http/1.1` | WebSocket + Protobuf/YaFF + RealityMode2 |
| **TewFai** | Да | Да | `outbounds` / `inbounds` | Да | Да (с XOR-FEC) | `h3` (QUIC) / TLS | QUIC/TCP, X25519 + ML-KEM-768, shaper/morphing |
| **WDTT / qWDTT / CSQTT** | Да | Да | `outbounds` / `inbounds` | Да | Да (через `smoltcp`) | — | WebRTC / DTLS / SRTP / TURN |
| **MTProto** | Да | Да | `outbounds` / `inbounds` | Да | Нет | — (`http/1.1` для `kws`) | `mtproto`, `mtproxy`, `telegram-ws`/`kws` |
| **OpenConnect** | Да (`outbounds`) | Да | `outbounds` / `inbounds` | Да | Да (в IP/ESP режиме) | `http/1.1` | AnyConnect CSTP, GlobalProtect, Pulse, DTLS/ESP |
| **TrustTunnel** | Да | Да | `outbounds` / `inbounds` | Да | Да (`_udp2` CONNECT) | `h2` (TCP) / `h3` (QUIC) | HTTP/2 и HTTP/3 CONNECT |
| **OpenVPN** | Да (`openvpn-client`) | Нет (`openvpn-server`: check) | `endpoints` | Да | Да (через `smoltcp`) | — | Static-key V1, UDP/TCP, MSS clamping |
| **WireGuard / AWG 2.0/3.x** | Да | Через `endpoints` | `endpoints` | Да | Да (L3 IP-туннель) | — | Noise_IKpsk2, AWG 2.0/3.x, port hopping, QUIC/MASQUE |
| **Tailscale** | Да | Через mesh / exit node | `endpoints` | Да | Да (L3 mesh) | — | Control (`ts2021`), STUN, DERP, DISCO, MagicDNS |
| **MASQUE (RFC 9484)** | Да | Да | `outbounds` / `inbounds` | Да | Да (L3 CONNECT-IP) | `h3` / `h2` (`auto`) | Cloudflare WARP / standard, capsules, `smoltcp` |

> Все потоковые inbound-протоколы поддерживают централизованный перехват `UoT` (`sp.v2.udp-over-tcp.arpa` и `sp.udp-over-tcp.arpa`).

---

## 2. Матрица совместимости с внешними ядрами и панелями

| Протокол / режим | `sing-box` | `sing-box-extended` | `xray-core` | `mihomo` | `podkop` | Панели (`3x-ui`, `Marzban`, `Remnawave`, `Pasarguard`, `Hiddify`, `Happ`) |
| --- | --- | --- | --- | --- | --- | --- |
| **VLESS** (plain / TLS / REALITY / Vision) | Двусторонняя | Двусторонняя | Двусторонняя | Двусторонняя | Двусторонняя | Полный импорт URI/JSON + REALITY PQ |
| **VLESS `encryption: mlkem768x25519plus`** | — | Двусторонняя | Двусторонняя | — | Частично | `3x-ui` / `Remnawave` / `Happ` (URI + Xray JSON) |
| **VLESS / Trojan / VMess + XHTTP** | — | Двусторонняя | Двусторонняя | Клиент | Двусторонняя | `3x-ui` / `Remnawave` / `Marzban` (`extra` + `xmux`) |
| **VMess** (AEAD / legacy, transports, mux) | Двусторонняя | Двусторонняя | Двусторонняя | Двусторонняя | Двусторонняя | Полный импорт `vmess://` (JSON и URI) |
| **Trojan** (TCP/UDP, transports, fallback) | Двусторонняя | Двусторонняя | Двусторонняя | Двусторонняя | Двусторонняя | Полный импорт `trojan://` / `trojan-go://` |
| **Shadowsocks** (AEAD + 2022 BLAKE3 + UoT) | Двусторонняя | Двусторонняя | Двусторонняя | Двусторонняя | Двусторонняя | SIP002, SIP008, Clash YAML |
| **Hysteria2** (plain + Salamander + port hop) | Двусторонняя | Двусторонняя | — | Двусторонняя | Двусторонняя | `hy2://` / `hysteria2://` (`mport`, `obfs`) |
| **Hysteria2 Gecko / `finalmask`** | — | Двусторонняя | Двусторонняя (`finalmask`) | — | Двусторонняя | `3x-ui` / `Remnawave` (`fm` / `finalmask`) |
| **TUIC v5** (`native` / `quic` / UoT / 0-RTT) | Двусторонняя | Двусторонняя | — | Двусторонняя | Двусторонняя | `tuic://` / `tuic5://` |
| **AnyTLS** | Двусторонняя | Двусторонняя | — | Двусторонняя | Двусторонняя | `anytls://` |
| **ShadowTLS v2 / v3** | Двусторонняя | Двусторонняя | — | Двусторонняя | Двусторонняя | `shadowtls://` / Clash YAML |
| **NaiveProxy** (H2 / H3 + UoT) | Двусторонняя | Двусторонняя | — | — | Двусторонняя | `naive+https://` / `naive+quic://` |
| **Snell v4 / v5 / v6** | — | Двусторонняя (`v4–v6` outbound, `v5–v6` inbound) | — | Клиент (v4) | — | `snell://` / Clash YAML |
| **Mieru v3** | — | Двусторонняя (`mbox`) | — | Клиент | — | `mieru://` / `mierus://` |
| **WireGuard / AmneziaWG 2.0 / 3.x** | WG | WG + AWG | WG | WG + AWG | WG + AWG | `.conf` INI, `vpn://`, `awg://`, `wg://` |
| **Tailscale / MASQUE / FPTN / OpenConnect / TrustTunnel / TewFai / WDTT / MTProto / OpenVPN** | Tailscale | Все | — | — | Частично | Нативные токены/URI (`fptn:`, `masque://`, `tg://proxy`, `tewfai://`, `wdtt://`) |

---

## 3. Потоковые прокси-протоколы

### 3.1. VLESS (Vision + `mlkem768x25519plus`)

#### Базовый проводной формат (версия `0x00`)

```text
Запрос клиента:
+--------+------------+------------+-----------+---------+------------+-----------+
| Ver=0  | UUID (16B) | AddonsLen  | Addons    | Cmd(1B) | Port (2B)  | Addr      |
|  0x00  |  raw bytes |   (1 B)    | Protobuf  | 1/2/3   | u16 BE     | [ATYP][A] |
+--------+------------+------------+-----------+---------+------------+-----------+

Ответ сервера (отправляется лениво с первыми данными):
+--------+------------+-----------+
| Ver=0  | AddonsLen  | Addons    |
|  0x00  |   (1 B)    | (обычно 0)|
+--------+------------+-----------+
```

- **Команды (`Cmd`)**: `0x01` = TCP, `0x02` = UDP (кадрирование `[len: u16 BE][payload]`), `0x03` = MUX (`XUDP` / `sing-mux`; при `0x03` поле адреса в заголовке запроса опускается).
- **Типы адресов VLESS**: `0x01` = IPv4 (4 Б), `0x02` = домен (`[len: u8][bytes]`), `0x03` = IPv6 (16 Б). Обратите внимание: порт передаётся **перед** типом адреса.
- **Addons (Protobuf)**: для потока `xtls-rprx-vision` записывается поле 1 length-delimited (`0x0A 0x11 "xtls-rprx-vision"`).

#### Поток `xtls-rprx-vision`

Vision оборачивает начальную фазу передачи поверх TLS 1.3 (или REALITY) во временные кадры паддинга без повторного шифрования полезной нагрузки:

```text
+----------+----------------+----------------+-----------+-----------+
| Cmd (1B) | ContentLen(2B) | PaddingLen(2B) | Content   | Padding   |
| 0/1/2    |    u16 BE      |     u16 BE     |  bytes    |  random   |
+----------+----------------+----------------+-----------+-----------+
```

- Команды: `0x00` (`CommandPaddingContinue`), `0x01` (`CommandPaddingEnd` — однократный переход к сырому потоку), `0x02` (`CommandPaddingDirect` — переход к прямому нешифрованному/нулевому ретранслированию внутренней TLS 1.3-сессии в обе стороны).
- Для внутреннего TLS-рукопожатия малые записи дополняются до `900..1400` байт; для не-TLS трафика фаза паддинга завершается через `8` пакетов (`PACKETS_TO_FILTER`).
- На сервере поддерживаются `fallback`, `fallback_for_alpn` и `tarpit` при невалидных запросах.

#### Постквантовое шифрование VLESS (`encryption` / `decryption`)

Формат строки конфигурации:
`mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>[.<padding>...].<key>...`

- Режимы внешнего вида (`appearance`): `native` (заголовки AEAD, оформленные под TLS 1.3), `xorpub` (XOR с публичным ключом), `random` (полностью случайный поток).
- Ключи: X25519 (32 Б) и ML-KEM-768 (1184 Б публичный ключ на клиенте / 64 Б seed на сервере), закодированные в Base64.
- Поддерживаются режимы `0rtt` и `1rtt` (на сервере задаётся время жизни тикета), совместимые с `xray-core` и `sing-box-extended`, как без `flow`, так и совместно с `xtls-rprx-vision`.

---

### 3.2. VMess (AEAD и Legacy)

- **Аутентификация**:
  - **AEAD (`alter_id == 0`, стандарт)**: 16-байтный `AuthID` (AES-128-ECB от `[timestamp: u64 BE][rand: u32][crc32: u32]` с ключом KDF `"AES Auth ID Encryption"`), затем 18-байтная зашифрованная длина заголовка (AES-128-GCM, KDF `"VMess Header AEAD Key_Length"` / `"Nonce_Length"`, AAD = `AuthID`), затем 8-байтный случайный connection nonce и зашифрованный заголовок запроса (AES-128-GCM, KDF `"VMess Header AEAD Key"` / `"Nonce"`, AAD = `AuthID`).
  - **Legacy (`alter_id > 0`)**: HMAC-MD5 аутентификация от временной метки и производных UUID + AES-128-CFB шифрование заголовка (поддерживается на клиенте и сервере для старых панелей).
- **Шифры полезной нагрузки (`security`)**: `auto` (на клиенте выбирается `aes-128-gcm` при аппаратном AES либо `chacha20-poly1305`), `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero`.
- **Опции кадрирования**: `global_padding` (случайный паддинг длины чанков), `authenticated_length` (AEAD-защита 2-байтной длины чанка), `packet_encoding` (`""`, `"packetaddr"`, `"xudp"`).

---

### 3.3. Trojan

- Требует TLS (или REALITY) на транспортном уровне.
- **Формат заголовка запроса**:
  ```text
  [hex(SHA-224(password)): 56 ASCII bytes]\r\n[Cmd: 1B (0x01 TCP / 0x03 UDP)][SOCKS5 Addr: 0x01/0x03/0x04][Port: 2B BE]\r\n[Payload...]
  ```
- **UDP-кадры** (`Cmd = 0x03`): `[SOCKS5 Addr][Port: 2B BE][Length: 2B BE]\r\n[UDP Payload]`.
- На inbound поддерживаются многопользовательская аутентификация, `fallback`, `fallback_for_alpn`, `tarpit`, потоковые транспорты и `h2mux`.

---

### 3.4. Shadowsocks (AEAD + 2022 BLAKE3)

#### Поддерживаемые шифры (`method`)

| Семейство | Методы | Размер ключа / соли |
| --- | --- | --- |
| **Shadowsocks 2022 (BLAKE3)** | `2022-blake3-aes-128-gcm` (16 Б), `2022-blake3-aes-256-gcm` (32 Б), `2022-blake3-chacha20-poly1305` (32 Б) | PSK в Base64; для multi-user формат `server_psk:user_psk` (EIH — Extensible Identity Headers, AES-ECB-зашифрованные 16-байтные хэши `BLAKE3(user_psk)[..16]`) |
| **AEAD (SIP004/007)** | `aes-128-gcm` (16 Б), `aes-256-gcm` (32 Б), `chacha20-ietf-poly1305` (32 Б), `xchacha20-ietf-poly1305` (32 Б) | HKDF-SHA1(`EVP_BytesToKey(password)`, `salt`, `"ss-subkey"`) |
| **Потоковые / без шифрования** | `chacha20-ietf`, `xchacha20`, `none` | Legacy / туннель внутри внешнего шифрования |

- **Проводной формат Shadowsocks 2022**:
  - TCP: `[salt][EIH...][fixed_header (type=0/1, timestamp u64, next_len u16) + tag][variable_header (addr, pad_len, padding, initial_payload) + tag][chunks...]`. Проверка временного окна `±30 s` защищает от повторов.
  - UDP: отдельный сессионный заголовок `[session_id: u64][packet_id: u64]` (зашифрованный AES-ECB для `aes-*` или XChaCha20 с 24-байтным nonce для `chacha20`), затем AEAD-тело с `type`, `timestamp`, `padding` и адресом назначения.
- Поддерживаются `udp_over_tcp` (v1/v2), `multiplex` (`h2mux`), а также SIP003-плагины (`obfs-local`/`simple-obfs`, `v2ray-plugin`).

---

## 4. Протоколы поверх QUIC и современного TLS

### 4.1. Hysteria и Hysteria2

> Статус Hysteria v1: конфигурация `type: "hysteria"` валидируется для обратной совместимости схем, однако исполняемый стек реализует **Hysteria2**.

#### Проводной контракт Hysteria2

- **Транспорт**: QUIC + TLS 1.3, ALPN строго `["h3"]`.
- **Аутентификация (HTTP/3)**:
  - Клиент отправляет `POST https://hysteria/auth` с заголовками:
    - `Hysteria-Auth`: пароль;
    - `Hysteria-CC-RX`: клиентская пропускная способность приёма в байт/с (`down_mbps * 125_000`, либо `0`);
    - `Hysteria-Padding`: случайная строка `[a-zA-Z0-9]` переменной длины.
  - Успешный ответ сервера: статус **`233`** с заголовками `Hysteria-UDP: true|false`, `Hysteria-CC-RX: <bytes/s | auto>` и `Hysteria-Padding`.
- **Управление перегрузкой**: при согласовании положительного `Hysteria-CC-RX` (и заданного `up_mbps`) включается контроллер **Brutal** (pacing по целевой скорости с ограниченной компенсацией потерь); при `auto` / `0` используется BBR.
- **TCP-запрос** (двунаправленный QUIC-поток):
  ```text
  [FrameType = 0x401 (varint)][AddrLen (varint)][Addr "host:port"][PadLen (varint)][Padding]
  Ответ: [Status (1B: 0=OK)][MsgLen (varint)][Msg][PadLen (varint)][Padding]
  ```
- **UDP-датаграммы** (QUIC DATAGRAM, `HY2_MAX_UDP = 4096` Б, с фрагментацией/сборкой):
  ```text
  [SessionID: u32 BE][PacketID: u16 BE][FragID: u8][FragCount: u8][AddrLen: varint][Addr "host:port"][Payload]
  ```
- **Маскировка `Salamander` и `Gecko` (`finalmask`)**:
  - `salamander`: каждый UDP-пакет кодируется как `[salt: 8 B] || (payload XOR BLAKE2b-256(password || salt))` (ключ повторяется циклически по 32 байта).
  - `gecko` (включая синтаксис Xray `finalmask`): добавляет слой управляемой фрагментации/размеров пакетов (`min_packet_size`, `max_packet_size`) поверх Salamander.
- **Port hopping**: поля `server_ports` (диапазоны `start:end`) и `hop_interval` периодически переключают порт назначения UDP-сокета QUIC-соединения без разрыва сессии.

---

### 4.2. TUIC v5

- **Транспорт**: QUIC + TLS 1.3 (ALPN `h3` или пользовательский). Версия протокола `0x05`.
- **Аутентификация (EKM)**: на однонаправленном QUIC-потоке отправляется `CMD_AUTHENTICATE (0x00)`:
  ```text
  [Ver=0x05][Cmd=0x00][UUID: 16B][Token: 32B = TLS Exported Keying Material(label=UUID, context=password)]
  ```
- **Команды**:
  - `0x01` (`CMD_CONNECT`) — двунаправленный поток TCP: `[0x05][0x01][TUIC Addr]`.
  - `0x02` (`CMD_PACKET`) — UDP-пакет: `[0x05][0x02][AssocID: u16][PktID: u16][FragTotal: u8][FragID: u8][Size: u16][TUIC Addr][Data]`. Передаётся либо через QUIC DATAGRAM (`udp_relay_mode: "native"`), либо через однонаправленные QUIC-потоки (`udp_relay_mode: "quic"`).
  - `0x03` (`CMD_DISSOCIATE`) — завершение UDP-ассоциации `[0x05][0x03][AssocID: u16]`.
  - `0x04` (`CMD_HEARTBEAT`) — 2-байтная датаграмма `[0x05][0x04]` (по умолчанию каждые 10 с).
- **Режим `udp_over_stream: true`**: открывает `CMD_CONNECT` на magic-адрес UoT v2 (`sp.v2.udp-over-tcp.arpa:0`).
- **0-RTT (`zero_rtt_handshake: true`)**: позволяет отправлять аутентификацию и первые потоки в 0-RTT QUIC.

---

### 4.3. AnyTLS

Потоковый мультиплексированный протокол поверх TLS 1.3 с настраиваемой политикой длин записей (`padding_scheme`).

- **Аутентификация и фрейминг**: поверх TLS 1.3 передаются кадры с 7-байтным заголовком `[Cmd: u8][StreamID: u32 BE][Length: u16 BE][Payload (<= 65535 B)]`.
- **Команды фреймов**:
  - `0` `CMD_WASTE` (паддинг), `1` `CMD_SYN` (открытие потока), `2` `CMD_PSH` (данные), `3` `CMD_FIN` (закрытие потока), `4` `CMD_SETTINGS` (клиентские настройки / версия), `5` `CMD_ALERT`, `6` `CMD_UPDATE_PADDING` (обновление схемы паддинга от сервера), `7` `CMD_SYNACK` (подтверждение потока), `8` `CMD_HEART_REQUEST`, `9` `CMD_HEART_RESPONSE`, `10` `CMD_SERVER_SETTINGS`.
- **UDP**: туннелируется автоматически через `UoT` v2 (`sp.v2.udp-over-tcp.arpa:0`) внутри логического потока AnyTLS.
- **Пул сессий**: долгоживущие TLS-сессии с idle-пулом (`idle_session_check_interval`, `idle_session_timeout`, `min_idle_session`).

---

### 4.4. ShadowTLS v2 / v3

Прозрачный маскировочный слой, использующий настоящий TLS 1.3 handshake стороннего легитимного сервера (`handshake.server`) в качестве фасада.

- **Маркер аутентификации в TLS ClientHello `Session ID` (32 байта)**:
  - **v2**: `HMAC-SHA1(password, challenge_random)[..20] || timestamp_u32_BE || random[8]`.
  - **v3**: `random_prefix[28] || HMAC-SHA1(password, prefix)[..4]`. После завершения реального TLS 1.3 handshake сервер переключает соединение на проксирование полезного потока, маскируя кадры под TLS Application Data (`0x17 0x03 0x03`) с HMAC-аутентификацией записей (v3, совместимо с `strict_mode` против активных зондов).
- **Серверные параметры**: `users` / `password`, `handshake`, `handshake_for_server_name` (выбор маскировочного сервера по SNI), `strict_mode`, `wildcard_sni`.
- **Использование**: обычно применяется как `detour` для Shadowsocks, VMess или VLESS.

---

### 4.5. NaiveProxy (H2 / H3 + Padding + UoT)

- **Транспорт**:
  - **HTTP/2** (`quic: false`, по умолчанию): TLS с ALPN `["h2"]`, пул долгоживущих H2-соединений.
  - **HTTP/3** (`quic: true`): QUIC с ALPN `["h3"]`, настраиваемый congestion control (`bbr`, `cubic`, и др.).
- **Запрос туннеля**: метод `CONNECT` с `:authority = <dest_host>:<dest_port>`, заголовком `proxy-authorization: Basic <base64(user:pass)>` и обязательным заголовком `Padding` (30–62 байт: 16 символов из набора `!#$()+<>?@[]^`{}`, дополненных символами `~`).
- **Кадрирование паддинга**: первые **8** блоков данных в каждом направлении обрамляются заголовком `[len: u16 BE][pad_len: u8][data: len B][zeros: pad_len B]`; начиная с 9-го блока поток идёт без обёртки.
- **UDP**: требует `udp_over_tcp` (v1 или v2); открывается `CONNECT` на `sp.v2.udp-over-tcp.arpa:0` (или `sp.udp-over-tcp.arpa:0`).

---

## 5. Специализированные и альтернативные прокси-протоколы

### 5.1. Snell v4 / v5 / v6

- **Версии**: клиент (outbound) поддерживает версии `4`, `5`, `6`; сервер (inbound) — версии `5` и `6`.
- **Криптография**: сессионный ключ AES-128-GCM выводится из PSK и случайной соли через Argon2.
- **Команды**: `CMD_CONNECT_V2` (TCP, с eager-отправкой заголовка, ответом сервера и zero-chunk EOF для переиспользования соединения в пуле `reuse`) и `CMD_UDP` / `UDP_FORWARD` (нативная пересылка UDP-датаграмм с адресом в каждом пакете).
- **Обфускация (`obfs`)**: опциональные обёртки `http` и `tls` (с параметром `host`).
- **Версия v6**: три режима записи поверх того же протокола запросов — `default` (профильное шейпирование с солевым блоком, префиксами записей, детерминированным паддингом и перемешиванием полезной нагрузки), `unshaped` (AEAD с нулевым паддингом) и `unsafe-raw` (открытые заголовки).

---

### 5.2. Mieru v3

- **Шифрование**: `XChaCha20-Poly1305` с ключом, выводимым из `username`, `password` и 2-минутной временной соли.
- **Nonce и идентификация пользователя**: 24-байтный nonce передаётся открыто в начале направления (в TCP инкрементируется на `1` для каждого последующего запечатывания метаданных и данных; в UDP каждый пакет несёт свой nonce). Последние 4 байта nonce содержат подсказку `SHA-256(user || nonce[..16])[..4]`, позволяющую серверу находить пользователя за O(1).
- **Полезная нагрузка сессии**: пара SOCKS5 request / reply **без** этапа согласования метода аутентификации.
- **Транспорты**: TCP и UDP, поддержка диапазонов `server_ports` и параметров совместимости `multiplexing` / `traffic_pattern`.

---

### 5.3. FPTN (WebSocket + YaFF/Protobuf + RealityMode2)

Клиент и сервер полностью совместимы с эталонным `fptn-project/fptn`:

1. **Авторизация**: `POST /api/v1/login` (возвращает JWT-токен; автоматически повторяется при отклонении WebSocket).
2. **TLS-идентификация**: проверка сертификата сервера по 32-символьному hex `md5_fingerprint` (пиннинг) и штамп времени `SHA-1(htonl(now))[..4]` в TLS Session ID.
3. **Режим `RealityMode2` (`obfuscation`)**:
   - На сыром TCP отправляется маскировочный ClientHello, собранный из шаблонов CamouflageTLS (профили Chrome 145–149, Firefox 149–151, Safari 26.4–26.5, Yandex 24–26.4) со свежим random, настроенным SNI и decoy Session ID (32 байта с меткой `SHA-1(htonl(now))[..4]` на смещении **14**, сервер проверяет окно `±120 s`).
   - Ожидается ответ сервера (бюджет 6 с, тишина 300 мс), отправляется ChangeCipherSpec (пауза 150 мс), подключается `TlsObfuscator2` (пауза 150 мс), внутри него проходит настоящий TLS-handshake, после чего обфускатор отключается.
4. **Туннель данных**: WebSocket на `/api/v1/fptn`, переносящий пакеты IPv4 в бинарных кадрах через сериализатор **Protobuf** либо **YaFF** (`X-Serializer: yaff` — zero-copy плоский Little-Endian бинарный формат с 4-байтным корневым смещением и `TypedLimit_`).
5. **Сетевой стек**: выделенный сервером клиентский IPv4 обслуживается встроенным userspace-стеком `smoltcp` (TCP и UDP).

---

### 5.4. TewFai (FEC + Shaper + QUIC/TCP)

Протокол с поддержкой двух транспортов (`QUIC`, `transport_id = 0` и `TCP`, `transport_id = 1`) и автоматическим переключением/ротацией:

- **Рукопожатие и криптография (`HELLO` / `HELLO_OK`)**:
  - Взаимная аутентификация по `HMAC-SHA256` на ключе `PSK = SHA-256(uuid | password)`:
    - клиентский тег привязывает `transport_id` (`"tewfai hello" || transport_id || body`);
    - серверный тег привязывает `client_nonce` (`"tewfai hello_ok" || client_nonce || body`) для защиты от replay.
  - Эфемерный обмен ключами X25519 (с отбраковкой точек малого порядка) + опциональный постквантовый гибрид **ML-KEM-768** (`FLAG_PQC`).
- **XOR-FEC для UDP (`FLAG_FEC = 0x04`)**:
  - Код чётности `(k, k+1)` без внешних зависимостей (по умолчанию `k = 4`: 4 датаграммы + 1 пакет чётности = +25% накладных расходов), восстанавливающий любую 1 потерянную датаграмму в группе без ожидания ретрансмита.
  - Заголовок внутри `UDP_DGRAM`: `[group_id: u16 BE][shard_idx: u8][group_sz: u8]` (4 Б). Пакет чётности (`shard_idx == group_sz`) содержит `[xor_len: u16 BE][xor_bytes]` для точного восстановления длины пакетов переменного размера.
- **Шейпер и морфинг (`FLAG_SHAPER`)**:
  - Профили морфинга (`browsing`, `video`, `webrtc`, `bulk`): дополнение первых 30 чанков сессии (или 16 чанков после 200 мс паузы) кадрами `PAD` (`0x0A`) до целевого распределения длин.
  - Token-bucket pacing (`fixed` или `adaptive`) с квантом 10–20 мс и лимитом очереди сессии `256 KiB`.

---

### 5.5. WDTT / qWDTT / CSQTT (WebRTC / DTLS / SRTP / TURN)

- Полностью userspace-реализация (поверх `smoltcp` и `wireguard::noise`), поддерживающая режимы `wg`, `raw` и `csqtt` на клиенте и сервере.
- Транспортная обёртка имитирует медиатрафик WebRTC: согласование ретранслятора **TURN**, установка **DTLS**-сессии, инкапсуляция кадров в **SRTP** (настраиваемые медиапрофили и режим SRTP) с поддержкой нескольких параллельных воркеров (`workers`) и MTU по умолчанию `1280`.

---

### 5.6. MTProto (`obfuscated2` + `telegram-ws` / `kws`)

Поддерживает три режима работы на клиенте (и полноценный серверный inbound):

1. **`mtproto`** (по умолчанию): отправка 64-байтного обфусцирующего заголовка `obfuscated2` (AES-256-CTR с ключом, смешанным с 16-байтным `secret`), кадрированный протокол с указанием назначения в первом пакете.
2. **`mtproxy`**: быстрый некадрированный режим после начального рукопожатия назначения.
3. **`telegram-ws` (алиас `kws`)**: нативный WebSocket-мост Telegram. Инспектирует 64-байтный заголовок `obfuscated2` клиента (или определяет DC по CIDR целевого IP) для извлечения целевого датацентра Telegram (`±1..=±5`), открывает `wss://kws{dc}[-1].web.telegram.org/apiws` (ALPN `http/1.1`, subprotocol `binary`), ведёт per-DC cooldown 60 с при отказах и прозрачно откатывается на прямой TCP с воспроизведением 64-байтного заголовка, если upgrade не удался или трафик не является MTProto `obfuscated2`.

---

### 5.7. OpenConnect

Поддерживает три протокольных диалекта (`flavor`) на outbound (в `outbounds[]`) и серверном inbound:
- **Cisco AnyConnect (CSTP)**: TLS + HTTP `CONNECT`, кадры с магией `STF\x01`, длиной и типом пакета; опциональный UDP DTLS-канал.
- **Palo Alto GlobalProtect**: `GET`-рукопожатие с маркером `START_TUNNEL` и 16-байтным заголовком каждого кадра (магия, EtherType, длина); опциональный UDP ESP.
- **Juniper / Pulse**: бинарное согласование конфигурации и ESP over UDP.
- В режиме `ip` / `esp` туннель переносит L3 IP-пакеты через userspace-стек `smoltcp` (поддержка TCP и UDP).

---

### 5.8. TrustTunnel

- **Транспорт**: HTTP/2 поверх TLS (ALPN `h2`) либо HTTP/3 поверх QUIC (ALPN `h3`, при `quic: true`).
- **Аутентификация**: HTTP-заголовок `Authorization: Basic` (или `Proxy-Authorization`).
- **TCP**: стандартный HTTP/2 или HTTP/3 `CONNECT` на целевой `host:port`.
- **UDP**: `CONNECT` на псевдо-хост **`_udp2`**, внутри потока которого каждая датаграмма передаётся с собственным 4-кортежем адресов/портов.

---

## 6. Туннельные протоколы уровня L3 (`endpoints` / IP-стеки)

### 6.1. OpenVPN (`openvpn-client`)

- Подключается в секции `endpoints` как `type: "openvpn-client"` (схема `openvpn-server` проходит конфиг-валидацию, но серверный runtime не активен).
- Реализует инициатор OpenVPN **Static Key V1** (`-----BEGIN OpenVPN Static key V1-----`, 256 байт, разделяемые на два 128-байтных слота ключей шифрования и HMAC) поверх UDP или TCP.
- Интегрирован с userspace-стеком `smoltcp` для TCP и прямой инкапсуляцией IPv4 для UDP; поддерживает скользящее окно защиты от повторов (`ReplayWindow`), TCP MSS clamping, keepalive-таймеры, HMAC (`SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, опционально `RIPEMD160`) и блочные/AEAD-шифры OpenVPN.

---

### 6.2. WireGuard и AmneziaWG 2.0 / 3.x

Подключается в секции `endpoints` (`type: "wireguard"`), поддерживает как userspace-реализацию (Noise_IKpsk2 + `smoltcp`), так и ядерный WireGuard Linux (`system: true` при отсутствии AWG-обфускации).

#### Расширения AmneziaWG

| Поколение | Параметры | Проводное поведение |
| --- | --- | --- |
| **AWG 1.x / 2.0** | `jc`, `jmin`, `jmax` | Отправка `jc` случайных junk-пакетов длиной `jmin..=jmax` перед рукопожатием |
| **AWG 2.0** | `s1`, `s2`, `s3`, `s4` | Добавление случайного префикса-паддинга к сообщениям Init (`s1`), Response (`s2`), Cookie (`s3`) и Data (`s4`) |
| **AWG 2.0** | `h1`, `h2`, `h3`, `h4` | Подмена 4-байтных типов пакетов WireGuard (`1..4`) на фиксированные значения или диапазоны `lo-hi` |
| **AWG 2.0** | `i1`–`i5` (алиасы `j1`–`j3`) | CPS-цепочки (Custom Protocol Signature) пре-рукопожатных сигнатурных пакетов (`<b ...>`, `<r ...>`, `<t>`, `<c>`, `<rc ...>`, `<rd ...>`) |
| **AWG 3.x** | `header_protection_key` (`hpk`), `content_padding_addition`, `random_trailers`, `disable_cookies`, `itime`, `rekey_*`, `reject_after_time`, `keepalive_timeout`, `max_handshake_attempts` | Криптографическая защита заголовков, добавочный паддинг полезной нагрузки, случайные трейлеры, управление куками и рандомизация таймеров |
| **Port Hopping & Транспорты** | `server_ports`, `hop_interval`, `hop_interval_max`, AWG-over-QUIC / AWG-over-MASQUE | Периодическая смена порта UDP-пира и туннелирование WG/AWG поверх QUIC/MASQUE |

> Важно: декларативные макросы `id` / `ip` / `ib` (masquerade-генераторы `I1`) распознаются и отклоняются с явной ошибкой, чтобы исключить тихую деградацию к несовместимому трафику.

---

### 6.3. Tailscale

Подключается в секции `endpoints` (`type: "tailscale"`). Полностью самостоятельная pure-Rust реализация без привязки Go `tsnet`:

- **Control Plane**: регистрация и синхронизация карты сети (`netmap`) с `https://controlplane.tailscale.com` (или самохостинговым Headscale через `control_url`) по протоколу Noise `ts2021` с поддержкой `auth_key`, `ephemeral`, `hostname`, `state_directory`.
- **STUN (RFC 5389)**: определение внешнего NAT-маппинга (магия `0x2112A442`, `Binding Request/Response`).
- **DERP (Designated Encrypted Relay for Packets)**: ретрансляция зашифрованных WireGuard-пакетов при строгом NAT (фреймы `SERVER_KEY 0x01`, `CLIENT_INFO 0x02`, `SERVER_INFO 0x03`, `SEND_PACKET`, `RECV_PACKET`, `KEEP_ALIVE`).
- **DISCO**: аутентифицированный обмен пингами/путями поверх NaCl Box (магия `TS\xf0\x9f\x92\xac` + 32-байтный ключ + 24-байтный nonce) для выбора кратчайшего прямого UDP-маршрута.
- **Маршрутизация и MagicDNS**: поддержка `exit_node`, `exit_node_allow_lan_access`, `accept_routes`, `advertise_routes`, `advertise_exit_node`, `advertise_tags`, локального разрешения имён Tailnet (MagicDNS) и userspace IP-стека `smoltcp` (MTU `1280`).

---

### 6.4. MASQUE (RFC 9484 CONNECT-IP / Cloudflare WARP)

- **Профили (`profile`)**: `cloudflare` (совместимость с Cloudflare WARP) и `standard` (чистый RFC 9484).
- **Транспортные ветки (`vhttp` / `auto`)**:
  - `h3`: HTTP/3 Extended CONNECT (`:protocol = connect-ip`) + HTTP/3 DATAGRAM (RFC 9297/9298) поверх QUIC.
  - `h2`: HTTP/2 Extended CONNECT + инкапсуляция IP-пакетов в капсулы потока.
  - `auto`: старт с `h3` с автоматическим откатом на `h2` при недоступности UDP и экспоненциальными фоновыми проверками возврата на `h3`.
- **Капсулы RFC 9484**: `ADDRESS_ASSIGN (1)`, `ADDRESS_REQUEST (2)`, `ROUTE_ADVERTISEMENT (3)`.
- **Обработка IP-пакетов**:
  - Полный пересчёт контрольной суммы IPv4 с учётом длины заголовка IHL (включая IP-опции), декремент TTL / Hop Limit и валидация входящих датаграмм.
  - Генерация ICMP / ICMPv6 Packet Too Big при превышении MTU (минимальный MTU = `1280` по RFC 8200).
  - Поддержка TLS certificate pinning, mTLS (P-256 / ECDSA ключи) и встроенного `smoltcp` для TCP/UDP.
