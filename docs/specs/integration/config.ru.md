# Спецификация JSON-конфигурации

`tachyon-core` использует схему конфигурации в формате JSON, полностью совместимую с `sing-box`.

## Структура

Конфигурация представляет собой один JSON-объект.

### Секции верхнего уровня
- `log`: Настройка логирования (уровень, файл вывода).
- `dns`: Правила разрешения DNS и FakeIP.
- `inbounds`: Список точек входа (серверов).
- `outbounds`: Список точек выхода (клиентов).
- `endpoints`: Эндпоинты WireGuard/AmneziaWG.
- `route`: Правила маршрутизации, снифферы и наборы правил (RuleSet).
- `experimental`: Настройки Clash API и кэша.

## Пример конфигурации

```json
{
  "log": {
    "level": "warn",
    "output": "/var/log/tachyon.log"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "in",
      "listen": "::",
      "listen_port": 7890
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "outbound": "direct",
        "domain_suffix": ["example.com"]
      }
    ]
  }
}
```
