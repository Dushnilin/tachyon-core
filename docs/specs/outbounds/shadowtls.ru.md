# Исходящее подключение ShadowTLS

Оборачивает другое исходящее подключение в поддельный TLS-рукопожатие для обхода DPI, анализирующего TLS.

## Схема

| Поле | Тип | По умолчанию | Описание |
|------|-----|-------------|----------|
| `type` | string | — | Обязательно `"shadowtls"` |
| `tag` | string | — | Уникальный идентификатор исходящего подключения |
| `server` | string | — | Имя хоста или IP-адрес сервера ShadowTLS |
| `server_port` | integer | — | Порт сервера ShadowTLS |
| `version` | integer | `3` | Версия протокола: `1`, `2` или `3`. Рекомендуется v3 (защита от replay) |
| `password` | string | — | **Обязательно** для v2/v3. Пароль аутентификации |
| `detour` | string | — | Тег внутреннего прокси-исходящего (напр. Shadowsocks), которое нужно обернуть |
| `tls.enabled` | bool | — | **Обязательно**, должно быть `true` |
| `tls.server_name` | string | — | **Обязательно.** Реальный домен с валидным TLS-сертификатом для имитации |
| `tls.utls.enabled` | bool | `false` | Включить uTLS для эмуляции TLS-отпечатка браузера |
| `tls.utls.fingerprint` | string | — | Отпечаток uTLS: `"chrome"`, `"firefox"`, `"safari"`, `"ios"`, `"android"`, `"edge"`, `"360"`, `"qq"`, `"random"`, `"randomized"` |

> Dial-поля (`bind_interface`, `connect_timeout`, `domain_strategy` и др.) поддерживаются — см. общую документацию по dial.

## Пример

```json
{
  "type": "shadowtls",
  "tag": "shadowtls-out",
  "server": "192.0.2.1",
  "server_port": 443,
  "version": 3,
  "password": "st-password",
  "tls": {
    "enabled": true,
    "server_name": "www.apple.com",
    "utls": {
      "enabled": true,
      "fingerprint": "safari"
    }
  },
  "detour": "ss-out"
}
```

Внутреннее исходящее Shadowsocks, на которое ссылается `detour`:

```json
{
  "type": "shadowsocks",
  "tag": "ss-out",
  "server": "127.0.0.1",
  "server_port": 8388,
  "method": "2022-blake3-aes-128-gcm",
  "password": "ss-password"
}
```

## Примечания

- `detour` указывает на тег внутреннего прокси-исходящего (напр. Shadowsocks). ShadowTLS отвечает только за TLS-камуфляж; шифрование данных обеспечивает внутреннее исходящее.
- `tls.server_name` **должен** быть реальным доменом, TLS-рукопожатие которого воспроизводит настоящий браузер. Использование поддельного или self-signed домена лишает смысла всю схему.
- v3 — единственная версия с защитой от replay-атак; используйте её в production.
- uTLS (`tls.utls`) заставляет TLS `ClientHello` соответствовать конкретному браузерному отпечатку, что существенно повышает эффективность обхода DPI.
- `server`/`server_port` внутреннего исходящего обычно указывают на loopback или внутренний адрес; ShadowTLS устанавливает внешнее TCP-соединение.
