# Поля прослушивания (инбаунды)

Общий набор для всех инбаундов, которые слушают сокет: `mixed`, `socks`,
`http`, `vless`, `vmess`, `trojan`, `shadowsocks`, `shadowtls`, `anytls`,
`naive`, `hysteria2`, `tuic`, `fptn`.

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `listen` | string | `::` | Адрес прослушивания. `::` принимает соединения на всех интерфейсах, для IPv4 работает через двойной стек. |
| `listen_port` | uint16 | — | Порт прослушивания. Обязателен для всех инбаундов с сокетом: без него ядро не стартует. |
| `bind_interface` | string | — | Ограничить приём соединений одним интерфейсом. |
| `routing_mark` | uint32 | — | Метка маршрутизации (SO_MARK) для сокета. Число, не строка. |
| `reuse_addr` | boolean | — | SO_REUSEADDR. |
| `netns` | string | — | Сетевое пространство имён для сокета. |
| `disable_tcp_keep_alive` | boolean | — | Отключить TCP keep-alive на сокете. |
| `tcp_keep_alive` | boolean | — | Включить TCP keep-alive. |
| `tcp_keep_alive_interval` | string | — | Интервал keep-alive, вида `45s`. |
| `tcp_fast_open` | boolean | — | TCP Fast Open. |
| `tcp_multi_path` | boolean | — | Multipath TCP. |
| `udp_fragment` | boolean | — | Фрагментировать UDP-пакеты, превышающие MTU пути. |
| `udp_timeout` | string | — | Таймаут UDP-сессии, вида `30s` или `5m`. |
| `detour` | string | — | Тег аутбаунда, через который принимать соединения. |
| `proxy_protocol` | boolean | — | Читать заголовок PROXY protocol от клиента. |
| `proxy_protocol_accept_no_header` | boolean | — | Принимать соединения и без заголовка PROXY. |

## Пример

```json
{
  "type": "mixed",
  "tag": "mixed-in",
  "listen": "::",
  "listen_port": 2080,
  "tcp_fast_open": true,
  "udp_timeout": "5m"
}
```

## Проверка

`listen_port` — единственное обязательное поле среди этих. Валидатор отклоняет
значение, если оно не помещается в `uint16`, и указывает путь до поля:
`inbounds[0].listen_port: json: cannot unmarshal number 70000 into Go struct
field ListenInboundOptions.listen_port of type uint16`.
