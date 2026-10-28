# Спецификация CLI

`tachyon-core` предоставляет стандартный интерфейс командной строки для окружений OpenWrt и Linux.

## Команды

### `version`
Выводит текущую версию ядра.
```bash
tachyon-core version
```

### `check -c <path>`
Проверяет JSON-конфигурацию по пути `<path>`.
```bash
tachyon-core check -c /etc/tachyon/config.json
```
Выполняет валидацию схемы и семантическую проверку согласно контракту совместимости с `sing-box`.

### `run -c <path>`
Запускает ядро с указанной конфигурацией.
```bash
tachyon-core run -c /etc/tachyon/config.json
```

### `generate <type>`
Генерирует криптографические материалы.
- `reality-keypair`: Генерация пары ключей X25519 для REALITY.
- `wg-keypair`: Генерация пары ключей WireGuard/AmneziaWG.
- `tls-keypair <sni> [-m <months>]`: Генерация самоподписанного сертификата ECDSA P-256 и ключа (PEM).
- `uuid` / `rand`: Генерация UUID v4 или случайного ключа.

### `rule-set <command>`
Управление бинарными правилами SRS v5.
- `compile`: Компиляция JSON-правил в `.srs`.
- `match`: Проверка совпадения правил с целью.

## Переменные окружения
- `TACHYON_WORKERS`: Количество потоков-воркеров.
- `TACHYON_SMOL_TCP_BUF`: Размер буфера TCP-сокета для пользовательских стеков (в KiB).
