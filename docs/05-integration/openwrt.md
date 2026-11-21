# Интеграция `tachyon-core` на OpenWrt

Руководство охватывает установку, настройку службы `procd`, интеграцию с `nftables` (режимы `tproxy`, `redirect` и `tun`), защиту NAND/NOR флеш-памяти и эксплуатацию `tachyon-core` (v0.6.2) на OpenWrt 23.05, 24.10, 25.x и SNAPSHOT.

## Выбор пакета под архитектуру роутера

Определите архитектуру устройства командой:

```sh
uname -m
cat /etc/openwrt_release
```

| Архитектура OpenWrt | Релизный артефакт | Целевой профиль Rust | Примечание |
|---|---|---|---|
| `aarch64_cortex-a53`, `aarch64_generic` | `tachyon-core-aarch64-v0.6.2.{ipk,apk}` | `aarch64-unknown-linux-musl` | ARMv8 AES/PMULL/NEON (runtime-диспетчеризация) |
| `arm_cortex-a7*`, `arm_cortex-a9*` | `tachyon-core-armv7-v0.6.2.{ipk,apk}` | `armv7-unknown-linux-musleabihf` | ARMv7 hard-float (`vfpv3-d16`) |
| `arm_arm1176jzf-s_vfp`, ARMv6 | `tachyon-core-armv6-v0.6.2.{ipk,apk}` | `arm-unknown-linux-musleabi` | ARMv6 soft-float |
| `mipsel_24kc`, `mipsel_74kc` | `tachyon-core-mipsel-v0.6.2.{ipk,apk}` | `mipsel-unknown-linux-musl` | MIPS32r2 little-endian, soft-float (без аппаратного FPU) |
| `mips_24kc` | `tachyon-core-mips-v0.6.2.{ipk,apk}` | `mips-unknown-linux-musl` | MIPS32r2 big-endian, soft-float (без аппаратного FPU) |
| `x86_64` | `tachyon-core-x86_64-v0.6.2.{ipk,apk}` | `x86_64-unknown-linux-musl` | Базовый `x86-64` (J1900/J4125/N100/VM) + CPUID dispatch |
| `i386_pentium4` | `tachyon-core-i386_pentium4-v0.6.2.{ipk,apk}` | `i686-unknown-linux-musl` | 32-bit x86 с SSE2 |
| `riscv64_riscv64` | `tachyon-core-riscv64-v0.6.2.{ipk,apk}` | `riscv64gc-unknown-linux-musl` | RISC-V 64-bit GC |

Сборки для `mips` и `mipsel` компилируются со строго программной арифметикой с плавающей точкой (`+soft-float`, `mips32r2`), что исключает аварийное завершение `SIGILL` (код 132) на роутерах `ath79` и `ramips` (`24Kc` / `24KEc` / `1004Kc`) без блока FPU.

---

## Установка пакетов (`.ipk` и `.apk`)

Готовые пакеты `.ipk` и `.apk` содержат статически слинкованный musl-бинарник со встроенными корневыми сертификатами WebPKI и не объявляют жёстких зависимостей `Depends`, поэтому устанавливаются даже в автономном режиме. Ядерные модули для прозрачного перехвата (`tproxy`/`tun`) ставятся отдельно из репозитория OpenWrt.

### OpenWrt 23.05 / 24.10 (`opkg`)

```sh
opkg update
opkg install kmod-nft-tproxy kmod-tun ip-full
opkg install /tmp/tachyon-core-aarch64-v0.6.2.ipk
```

### OpenWrt 25.x / SNAPSHOT (`apk`)

```sh
apk update
apk add kmod-nft-tproxy kmod-tun ip-full
apk add --allow-untrusted /tmp/tachyon-core-aarch64-v0.6.2.apk
```

### Устанавливаемые файлы

| Путь | Назначение |
|---|---|
| `/usr/bin/tachyon-core` | Статический исполняемый файл ядра |
| `/etc/init.d/tachyon-core` | Скрипт службы `procd` |
| `/etc/config/tachyon-core` | Конфигурация UCI |
| `/etc/tachyon-core/config.json` | Базовая JSON-конфигурация |

Сценарий `postinst` после установки отключает самостоятельный автозапуск `/etc/init.d/tachyon-core`, чтобы не конфликтовать с внешними оркестраторами (если они управляют жизненным циклом ядра). Для автономной работы включите службу явно через UCI (см. ниже).

---

## Конфигурация `procd` и UCI

Файл `/etc/config/tachyon-core`:

```text
config tachyon-core 'main'
	option enabled '1'
	option user 'root'
	option conffile '/etc/tachyon-core/config.json'
	option workdir '/usr/share/tachyon-core'
	option log_stderr '1'
```

| Параметр UCI | По умолчанию | Описание |
|---|---|---|
| `enabled` | `0` | `1` — разрешить запуск службы. |
| `conffile` (или `config_file`) | `/etc/tachyon-core/config.json` | Путь к JSON-конфигурации или каталогу фрагментов. Если файл отсутствует, скрипт ищет `/tmp/tachyon-core/config.json`, затем резервный `/etc/tachyon-core/config.json.bak`. |
| `workdir` | `/usr/share/tachyon-core` | Рабочий каталог (`-D`). |
| `log_stderr` | `1` | Перенаправлять `stderr` процесса в системный журнал OpenWrt (`logread`). |

Что делает `/etc/init.d/tachyon-core` при запуске:
1. Создаёт `/dev/net/tun` при отсутствии и подгружает модули ядра `tun` и `inet_diag`.
2. Выполняет предварительную проверку `tachyon-core check -c "$config_file" -D "$working_directory"`. При ошибке автоматически переключается на резервную конфигурацию `/etc/tachyon-core/config.json.bak`, если она проходит `check`.
3. Запускает экземпляр под управлением `procd` со следующими параметрами:
   - `limits core="0"`, `limits nofile="65535 65535"`;
   - `env TACHYON_RULESET_SOFT_START="1" TACHYON_WORKERS="<число CPU>"`;
   - `oom_score_adj -500`, `term_timeout 15`, `respawn 3600 5 5`.

Включение и запуск автономной службы:

```sh
uci set tachyon-core.main.enabled='1'
uci commit tachyon-core
/etc/init.d/tachyon-core enable
/etc/init.d/tachyon-core start
```

---

## Настройка `nftables` и маршрутизации ядра

### Вариант 1: Прозрачное проксирование `tproxy` (IPv4 + IPv6, TCP + UDP)

Рекомендуемый режим для роутеров OpenWrt: обрабатывает и TCP, и UDP без создания виртуального L3-интерфейса и копирования пакетов через TUN. Требуются пакеты `kmod-nft-tproxy` и `ip-full`.

#### 1. Конфигурация `tachyon-core` (фрагмент)

Все исходящие сокеты должны помечаться `routing_mark` (например, `255` = `0xff`), чтобы трафик самого ядра не попадал обратно в правило `tproxy`:

```json
{
  "inbounds": [
    {
      "type": "tproxy",
      "tag": "tproxy-in",
      "listen": "::",
      "listen_port": 7895,
      "network": "tcp,udp",
      "udp_timeout": "5m"
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct",
      "routing_mark": 255
    },
    {
      "type": "vless",
      "tag": "proxy",
      "server": "edge.example.com",
      "server_port": 443,
      "uuid": "00000000-0000-4000-8000-000000000000",
      "routing_mark": 255
    }
  ],
  "route": {
    "default_mark": 255,
    "final": "proxy"
  }
}
```

#### 2. Политика маршрутизации (`ip rule` / `ip route`)

Направляем помеченные в `nftables` пакеты (`fwmark 0x1`) в локальную таблицу маршрутизации `100` на интерфейс `lo`:

```sh
# IPv4
ip rule add fwmark 0x1 lookup 100 pref 100
ip route add local 0.0.0.0/0 dev lo table 100

# IPv6 (при наличии IPv6 в LAN)
ip -6 rule add fwmark 0x1 lookup 100 pref 100
ip -6 route add local ::/0 dev lo table 100
```

#### 3. Таблица `nftables` (`/etc/nftables.d/90-tachyon-tproxy.nft`)

```nft
table inet tachyon_tproxy {
    set bypass_v4 {
        type ipv4_addr
        flags interval
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
            169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16,
            224.0.0.0/4, 240.0.0.0/4
        }
    }

    set bypass_v6 {
        type ipv6_addr
        flags interval
        elements = {
            ::/128, ::1/128, fe80::/10, fc00::/7, ff00::/8
        }
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        # Пропускаем уже установленные прозрачные сокеты
        meta l4proto { tcp, udp } socket transparent 1 meta mark set 0x1 accept

        # Не перехватываем локальные/частные адреса и трафик самого ядра
        meta mark 0xff return
        iifname "lo" return
        ip daddr @bypass_v4 return
        ip6 daddr @bypass_v6 return

        # Перехват LAN-трафика (TCP + UDP) на порт 7895
        iifname "br-lan" meta l4proto { tcp, udp } tproxy to :7895 meta mark set 0x1 accept
    }

    chain output {
        type route hook output priority mangle; policy accept;

        # Исключаем исходящие сокеты самого tachyon-core
        meta mark 0xff return
        ip daddr @bypass_v4 return
        ip6 daddr @bypass_v6 return

        # Перехват трафика с самого роутера (опционально)
        meta l4proto { tcp, udp } meta mark set 0x1
    }
}
```

Применение правил на OpenWrt с `fw4`:

```sh
nft -c -f /etc/nftables.d/90-tachyon-tproxy.nft
/etc/init.d/firewall reload
```

> Если в настройках `firewall` включён `flow_offloading` (`software` или `hardware`), перенаправляемый через `tproxy` трафик должен исключаться из offload, иначе ядро пропустит пакеты мимо цепочки `mangle`.

---

### Вариант 2: `redirect` (только TCP)

Инбаунд `redirect` восстанавливает исходный адрес назначения через `SO_ORIGINAL_DST` и не требует `kmod-nft-tproxy` и `ip rule`, однако **поддерживает только TCP** (UDP-трафик через `redirect` не проходит):

```json
{
  "inbounds": [
    {
      "type": "redirect",
      "tag": "redir-in",
      "listen": "0.0.0.0",
      "listen_port": 7892
    }
  ]
}
```

Правило `nftables`:

```nft
table inet tachyon_redirect {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "br-lan" ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 } \
            tcp dport 1-65535 redirect to :7892
    }
}
```

---

### Вариант 3: `tun` (виртуальный интерфейс)

Инбаунд `tun` создаёт интерфейс через `/dev/net/tun` (требуется `kmod-tun` и `ip-full`):

```json
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "mtu": 1500,
      "auto_route": true,
      "strict_route": true,
      "stack": "system"
    }
  ]
}
```

На OpenWrt необходимо разрешить форвардинг из `lan` в зону интерфейса `tun0` в `/etc/config/firewall`:

```text
config zone
	option name 'tachyon'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'
	list device 'tun0'

config forwarding
	option src 'lan'
	option dest 'tachyon'
```

---

## Защита NAND/NOR флеш-памяти

На встроенных роутерах корневая файловая система расположена на SPI-NOR или NAND-флеш с ограниченным ресурсом циклов перезаписи.

1. **Логи — только в `/tmp` (`tmpfs`)**:
   ```json
   {
     "log": {
       "level": "warn",
       "output": "/tmp/tachyon-core/tachyon-core.log",
       "timestamp": true
     }
   }
   ```
   При записи в файл `tachyon-core` автоматически усекает лог при достижении `2 MiB`, не позволяя исчерпать ОЗУ в `/tmp`.
2. **Кэш `cache.db` и трёхуровневая защита флеш-памяти**:
   - Наиболее бережный вариант — хранить весь кэш в ОЗУ:
     ```json
     {
       "experimental": {
         "cache_file": {
           "enabled": true,
           "path": "/tmp/tachyon-core/cache.db",
           "store_fakeip": true,
           "store_rdrc": true
         }
       }
     }
     ```
   - Если `cache_file.path` всё же указывает на постоянное хранилище под `/etc/` или `/usr/` (чтобы сохранять выбранные узлы и FakeIP между перезагрузками), движок на Linux автоматически разделяет данные на 3 уровня:
     - основной `cache.db` — редко меняющиеся настройки (выбранный узел, режим);
     - `<path>.volatile` — FakeIP и профили десинхронизации;
     - высокочастотные бакеты (кэш DNS, RDRC, счётчики LAN-устройств, задержки) и lock-файл автоматически перенаправляются в `/tmp/tachyon-core/<name>.ephemeral` и никогда не записываются на флеш.
3. **Кэш удалённых наборов правил `.trs`**: по умолчанию сохраняется в `/tmp/tachyon-rulesets/<tag>.trs` (в `tmpfs`). Не указывайте для часто обновляемых `rule_set` путь внутри `/etc/` или `/usr/`.

---

## Проверка работы и горячая перезагрузка

```sh
# 1. Проверка конфигурации перед применением
/etc/init.d/tachyon-core check

# 2. Проверить, пройдёт ли обновление без обрыва соединений
tachyon-core reload-preview --current /etc/tachyon-core/config.json /tmp/config.new.json

# 3. Горячая перезагрузка (отправляет SIGHUP процессу tachyon-core)
/etc/init.d/tachyon-core reload

# 4. Проверка версии и состояния службы
/etc/init.d/tachyon-core version
/etc/init.d/tachyon-core status

# 5. Диагностика через встроенный CLI-клиент API
tachyon-core api --url http://127.0.0.1:9090 /tachyon/health
tachyon-core api --url http://127.0.0.1:9090 /tachyon/memory
tachyon-core api --url http://127.0.0.1:9090 POST /tachyon/dns-check '{"domain":"example.com"}'

# 6. Просмотр журнала
logread -e tachyon-core
tail -n 50 /tmp/tachyon-core/tachyon-core.log
```
