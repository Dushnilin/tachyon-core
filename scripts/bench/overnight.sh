#!/bin/sh
# Ночь: только tachyon-core, каждый протокол по очереди — 10000 коннектов,
# трафик непрерывно, 20 минут на протокол. Готовые json'ы пропускаются,
# так что после падения просто запустите ещё раз и продолжится с места схода.
cd /tmp/bench || exit 1
ulimit -n 65535 2>/dev/null
# 10k коннектов через туннель = до 30k сокетов на loopback; узкий эфемерный
# диапазон (старт с 32768) их не вмещает
echo "1024 65535" > /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null
# дефолтный relay-буфер — 128 КиБ, два на коннект, и на каждом ядре: при
# 1500 коннектов это 384 МиБ на ядро и OOM на 727 МиБ роутера (убивали ядра
# на ~700 коннектах). 16 КиБ на loopback хватает с запасом
TACHYON_RELAY_BUF="${RELAY_BUF:-16384}"
export TACHYON_RELAY_BUF
python3 night_load.py --tachyon ./tachyon-core \
    --conns "${CONNS:-10000}" --minutes "${MINUTES:-20}" \
    --out-dir results --work /tmp/bench 2>&1 | tee -a night.log
