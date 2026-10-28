# Инбаунд: Shadowsocks

Серверная точка входа Shadowsocks с поддержкой классических шифров AEAD и спецификации Shadowsocks-2022 (`2022-blake3-*`) поверх TCP и UDP.

## Схема конфигурации

| Поле | Тип | Обязательно | Описание |
|---|---|---|---|
| `type` | string | Да | Должно быть `"shadowsocks"`. |
| `tag` | string | Нет | Уникальный идентификатор инбаунда. |
| `listen` | string | Да | Адрес прослушивания. |
| `listen_port` | uint16 | Да | Порт прослушивания. |
| `method` | string | Да | Шифр (`"2022-blake3-aes-128-gcm"`, `"2022-blake3-aes-256-gcm"`, `"2022-blake3-chacha20-poly1305"`, `"aes-128-gcm"`, `"aes-256-gcm"`, `"chacha20-ietf-poly1305"`, `"none"`). |
| `password` | string | Да | Пароль (или ключ в base64 для методов 2022). |
| `network` | string | Нет | `"tcp"`, `"udp"`, либо не указано (оба протокола). |
| `udp_timeout` | string | Нет | Таймаут UDP-сессии (например, `"5m"`). |

## Пример

```json
{
  "type": "shadowsocks",
  "tag": "ss-in",
  "listen": "::",
  "listen_port": 8388,
  "method": "2022-blake3-aes-128-gcm",
  "password": "base64-encoded-16-byte-key=="
}
```
