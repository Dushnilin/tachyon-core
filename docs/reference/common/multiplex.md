# Мультиплексирование

Блок `multiplex` у клиентских аутбаундов `shadowsocks`, `vmess`, `vless`,
`trojan`. Несколько логических потоков едут по одному транспортному соединению.

```json
"multiplex": {
  "enabled": true,
  "protocol": "h2mux",
  "max_connections": 4,
  "min_streams": 4,
  "max_streams": 0,
  "padding": true
}
```

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | boolean | — | Включить мультиплексирование. |
| `protocol` | string | — | `h2mux`, `smux` или `yamux`. Пустая строка — как в эталоне. |
| `max_connections` | uint32 | — | Максимум одновременных соединений. |
| `min_streams` | uint32 | — | Минимум потоков для открытия нового соединения. |
| `max_streams` | uint32 | — | Максимум потоков на соединение, `0` — без ограничения. |
| `padding` | boolean | — | Паддинг кадров. |

## Brutal

Вложенный блок для управления полосой:

```json
"multiplex": {
  "enabled": true,
  "protocol": "h2mux",
  "brutal": { "enabled": true, "up_mbps": 100, "down_mbps": 100 }
}
```

| Поле | Тип | По умолчанию | Описание |
|---|---|---|---|
| `enabled` | boolean | — | Включить Brutal. |
| `up_mbps` | uint32 | — | Скорость аплинка в Mbps. |
| `down_mbps` | uint32 | — | Скорость даунлинка в Mbps. |

Значение `protocol` проверяется независимо от `enabled`: неизвестное имя даёт
ошибку `outbounds[i].multiplex: unknown protocol: ...`.
