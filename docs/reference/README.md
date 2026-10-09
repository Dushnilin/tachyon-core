# Справочник конфигурации

Документация по схеме конфига `tachyon-core`. Описания полей соответствуют
тому, что принимает `check -c`: неизвестное поле отклоняется с указанием пути,
поэтому расхождение между этими страницами и валидатором означает ошибку в
документации, а не в схеме.

## Секции верхнего уровня

| Секция | Назначение |
|---|---|
| `log` | Уровень, вывод, метки времени. |
| `dns` | Резолверы, правила, кэш — [dns](dns.md). |
| `inbounds` | Точки входа — [inbounds/](inbounds/). |
| `outbounds` | Точки выхода — [outbounds/](outbounds/). |
| `endpoints` | Туннели WireGuard, AmneziaWG, OpenVPN — [endpoints](endpoints.md). |
| `route` | Правила маршрутизации, rule-set — [routing](common/routing.md). |
| `experimental` | Clash API, файл кэша. |
| `ntp` | Клиент синхронизации времени. |
| `http_clients` | Реестр HTTP-клиентов для загрузки списков. |

## Инбаунды

Принимаются конфигом и работают:

| Тип | Страница |
|---|---|
| `mixed` | [mixed](inbounds/mixed.md) — SOCKS4/4a/5 + HTTP CONNECT на одном порту. |
| `socks` | [socks](inbounds/socks.md) |
| `http` | [http](inbounds/http.md) |
| `direct` | [direct](inbounds/direct.md) |
| `redirect` | [redirect](inbounds/redirect.md) — прозрачный TCP через NAT. |
| `tproxy` | [tproxy](inbounds/tproxy.md) — прозрачный TCP и UDP. |
| `vless` | [vless](inbounds/vless.md) |
| `vmess` | [vmess](inbounds/vmess.md) |
| `trojan` | [trojan](inbounds/trojan.md) |
| `shadowsocks` | [shadowsocks](inbounds/shadowsocks.md) |
| `shadowtls` | [shadowtls](inbounds/shadowtls.md) |
| `anytls` | [anytls](inbounds/anytls.md) |
| `naive` | [naive](inbounds/naive.md) |
| `hysteria2` | [hysteria2](inbounds/hysteria2.md) |
| `tuic` | [tuic](inbounds/tuic.md) |
| `fptn` | [fptn](inbounds/fptn.md) |

Принимаются конфигом, но в рантайме не реализованы:

| Тип | Страница |
|---|---|
| `tun` | [tun](inbounds/tun.md) — код есть, инбаунд неработоспособен, разбор расхождений на странице. |
| `hysteria` | [hysteria](inbounds/hysteria.md) |
| `snell` | [snell](inbounds/snell.md) |
| `cloudflared` | [cloudflared](inbounds/cloudflared.md) |

## Аутбаунды

Принимаются конфигом и работают:

| Тип | Страница |
|---|---|
| `direct` | [direct](outbounds/direct.md) |
| `block` | [block](outbounds/block.md) |
| `socks` | [socks](outbounds/socks.md) |
| `http` | [http](outbounds/http.md) |
| `shadowsocks` | [shadowsocks](outbounds/shadowsocks.md) |
| `vless` | [vless](outbounds/vless.md) |
| `vmess` | [vmess](outbounds/vmess.md) |
| `trojan` | [trojan](outbounds/trojan.md) |
| `hysteria2` | [hysteria2](outbounds/hysteria2.md) |
| `tuic` | [tuic](outbounds/tuic.md) |
| `anytls` | [anytls](outbounds/anytls.md) |
| `naive` | [naive](outbounds/naive.md) |
| `snell` | [snell](outbounds/snell.md) |
| `masque` | [masque](outbounds/masque.md) — CONNECT-IP для Cloudflare WARP. |
| `shadowtls` | [shadowtls](outbounds/shadowtls.md) |
| `selector` | [selector](outbounds/selector.md) |
| `urltest` | [urltest](outbounds/urltest.md) |
| `chain` | [chain](outbounds/chain.md) |

Принимаются конфигом, но в рантайме не реализованы:

| Тип | Страница |
|---|---|
| `hysteria` | [hysteria](outbounds/hysteria.md) |
| `ssh` | [ssh](outbounds/ssh.md) |
| `fptn` | [fptn](outbounds/fptn.md) |
| `tor` | [tor](outbounds/tor.md) |
| `dns` | [dns](outbounds/dns.md) |
| `bridge` | [bridge](outbounds/bridge.md) |

## Общие блоки

| Блок | Страница |
|---|---|
| Поля прослушивания | [listen](common/listen.md) |
| Поля диалера | [dialer](common/dialer.md) |
| TLS клиента | [tls-client](common/tls-client.md) |
| TLS сервера | [tls-server](common/tls-server.md) |
| Транспорты | [transports](common/transports.md) |
| Мультиплексирование | [multiplex](common/multiplex.md) |
| Пользователи | [users](common/users.md) |
| Маршрутизация и sniff | [routing](common/routing.md) |

## Проверка конфига

```bash
tachyon-core check -c /etc/sing-box/config.json
```

Валидатор отклоняет неизвестные поля и сообщает путь до элемента, например
`inbounds[0].listen_port: json: cannot unmarshal number 70000 into Go struct
field ListenInboundOptions.listen_port of type uint16`. Это поведение
намеренно повторяет эталон: проверка должна отвергать ровно то же, что и
sing-box-lx, иначе расхождение всплывёт только в продакшене.
