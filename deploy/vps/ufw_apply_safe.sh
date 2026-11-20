#!/usr/bin/env bash
# Включение ufw на рабочей ВМ с аварийным watchdog (задача T-708; TZ §8.3, §14.5).
#
# Включение файрвола — операция, которая может отрезать собственный вход: если правило для
# 22/tcp отсутствует или указано криво, следующие SSH-соединения не поднимутся, а чинить
# их будет нечем. Поэтому перед применением запускается таймер, который сам выключает ufw,
# если администратор не отменил его после проверки нового входа.
#
#   sudo bash deploy/vps/ufw_apply_safe.sh
# затем из ДРУГОГО терминала проверить вход и снять watchdog:
#   ssh -i ~/.ssh/tbot/ssh-key-1795095923419 rusiksoft@153.51.172.30 'echo ok'
#   sudo kill <WATCHDOG_PID>

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WATCHDOG_SECONDS=150

nohup bash -c "sleep ${WATCHDOG_SECONDS}; /usr/sbin/ufw disable" >/tmp/ufw-watchdog.log 2>&1 &
watchdog_pid=$!
echo "WATCHDOG_PID=${watchdog_pid} (через ${WATCHDOG_SECONDS} с сам выключит ufw)"
echo "после проверки нового входа: sudo kill ${watchdog_pid}"

bash "${HERE}/firewall.sh" --apply
