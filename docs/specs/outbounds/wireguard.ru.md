# Исходящее подключение WireGuard

VPN-туннель WireGuard / AmneziaWG с поддержкой Full Cone NAT и опциональной обфускацией мусорными пакетами.

## Схема

| Поле | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `type` | string | — | Обязательно `"wireguard"` |
| `tag` | string | — | Уникальный идентификатор исходящего подключения |
| `server` | string | — | Имя хоста или IP-адрес пира (режим одного пира) |
| `server_port` | integer | — | Порт пира (режим одного пира) |
| `local_address` | string[] | — | **Обязательно.** CIDR-адреса локального туннельного интерфейса (напр. `["10.0.0.2/32", "fd00::2/128"]`) |
| `private_key` | string | — | **Обязательно.** Приватный ключ WireGuard в base64 |
| `peer_public_key` | string | — | **Обязательно** (один пир). Публичный ключ сервера в base64 |
| `pre_shared_key` | string | — | Опциональный pre-shared key (PSK) в base64 для дополнительного симметричного шифрования |
| `peers` | object[] | — | Список пиров для multi-peer режима; каждый содержит `server`, `server_port`, `public_key`, `pre_shared_key`, `allowed_ips` |
| `mtu` | integer | `1408` | MTU туннеля в байтах |
| `workers` | integer | кол-во CPU | Число параллельных обработчиков пакетов |
| `network` | string | `"tcp,udp"` | Поддерживаемые типы сети: `"tcp"`, `"udp"` или `"tcp,udp"` |
| `fake_packets` | string | — | AmneziaWG: диапазон количества мусорных пакетов, напр. `"5-10"` |
| `fake_packets_size` | string | — | AmneziaWG: диапазон размера мусорных пакетов в байтах, напр. `"40-100"` |
| `fake_packets_delay` | string | — | AmneziaWG: задержка между мусорными пакетами в мс, напр. `"20-250"` |
| `fake_packets_mode` | string | — | Режим обфускации AmneziaWG; на данный момент только `"m1"` |

> Dial-поля (`detour`, `bind_interface`, `connect_timeout`, `domain_strategy` и др.) поддерживаются — см. общую документацию по dial.

## Пример

### Стандартный WireGuard

```json
{
  "type": "wireguard",
  "tag": "wg-out",
  "server": "vpn.example.com",
  "server_port": 51820,
  "local_address": ["10.10.10.2/32", "fd00::2/128"],
  "private_key": "YBOnRyBsXxDG6cFi3MtSKE0E2dVoqDkqPVBRKwVPgGQ=",
  "peer_public_key": "mBpbKhQVEtmkQfb5nuY5e3RIcl0g/bVpADf1i2f+9Wk=",
  "mtu": 1280,
  "workers": 2
}
```

### AmneziaWG (обфускация мусорными пакетами)

```json
{
  "type": "wireguard",
  "tag": "awg-out",
  "server": "vpn.example.com",
  "server_port": 51820,
  "local_address": ["10.10.10.2/32"],
  "private_key": "YBOnRyBsXxDG6cFi3MtSKE0E2dVoqDkqPVBRKwVPgGQ=",
  "peer_public_key": "mBpbKhQVEtmkQfb5nuY5e3RIcl0g/bVpADf1i2f+9Wk=",
  "fake_packets": "5-10",
  "fake_packets_size": "40-100",
  "fake_packets_delay": "20-250",
  "fake_packets_mode": "m1"
}
```

### Несколько пиров (multi-peer)

```json
{
  "type": "wireguard",
  "tag": "wg-multi",
  "local_address": ["10.10.10.2/32"],
  "private_key": "YBOnRyBsXxDG6cFi3MtSKE0E2dVoqDkqPVBRKwVPgGQ=",
  "peers": [
    {
      "server": "peer1.example.com",
      "server_port": 51820,
      "public_key": "mBpbKhQVEtmkQfb5nuY5e3RIcl0g/bVpADf1i2f+9Wk=",
      "allowed_ips": ["0.0.0.0/0", "::/0"]
    }
  ]
}
```

## Примечания

- Поля `fake_packets_*` активируют режим AmneziaWG; все четыре должны быть заданы вместе. Без сервера AmneziaWG они не работают.
- Меньшие значения `mtu` (напр. `1280`) помогают избежать фрагментации через PPPoE и другие инкапсулирующие транспорты.
- `workers` по умолчанию равно числу логических CPU; уменьшение значения снижает конкуренцию за ядра на маломощных роутерах.
- Full Cone NAT разрешает входящие P2P-соединения в туннель — это стандартное поведение NAT для WireGuard.
- В multi-peer режиме поля `server`, `server_port` и `peer_public_key` верхнего уровня игнорируются — все данные пиров должны быть в массиве `peers`.
