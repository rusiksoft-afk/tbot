# Приёмка: файрвол, fail2ban и Docker на рабочей ВМ (T-708, остаток T-011, часть T-712)

Площадка: `153.51.172.30` (`compute-vm-2-4-74-ssd-1795094860175`, Yandex Cloud, Ubuntu 24.04.5 LTS,
`fv48ibn5ff3ff5gd0e3v`). Дата работ: 2026-11-20. Основание: TZ §8.3, §14.5, §14.6;
задачи **T-708** (файрвол/бан), **T-712** (Docker + pull по digest), **T-011** (базовая подготовка).

## 1. Состояние до

Группа безопасности Yandex Cloud не пропускала 80/443, на хосте `ufw` был `inactive`,
`fail2ban` не установлен, Docker не установлен. Замер снаружи (до изменения SG): `22` OPEN,
`80/443/5432/8080/9101` — соединения **терялись** (таймаут, без RST) — признак «фильтрует облако».

## 2. Шаг 1 — группа безопасности (сделал заказчик)

2026-11-20 заказчик изменил правила: входящий и исходящий трафик разрешён. Проверка снаружи
**до** включения `ufw` — пакеты стали доходить до хоста и получать RST:

```
80    bash: connect: Connection refused
443   bash: connect: Connection refused
5432  bash: connect: Connection refused
```

Разница «таймаут → отказ» и есть доказательство, что изменился именно облачный фильтр, а не хост.
Порядок действий и откат — `docs/runbook/yandex-sg.md`; замечание владельцу: SG теперь пропускает
весь входящий трафик, поэтому единственным фильтром портов стал `ufw` на самой машине
(зафиксировано в TZ OQ-13).

## 3. Шаг 2 — `ufw` (принятая конфигурация)

Артефакты в репозитории: `deploy/vps/ufw.rules` (что должно быть включено),
`deploy/vps/firewall.sh` (применение и `--revert`), `deploy/vps/ufw_apply_safe.sh`
(включение со страховкой).

Порядок включения важен: правила добавляются **до** `ufw enable`, иначе `deny incoming`
обрывает текущий SSH-вход. Дополнительно `ufw_apply_safe.sh` запускает watchdog: если новый
вход не поднимается, `ufw disable` выполняется сам через 150 с. Проверка велась новым
SSH-соединением при открытом резервном.

Фактическое состояние после применения:

```
Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
[ 1] 22/tcp   ALLOW IN  Anywhere        [ 4] 22/tcp (v6)   ALLOW IN  Anywhere (v6)
[ 2] 80/tcp   ALLOW IN  Anywhere        [ 5] 80/tcp (v6)   ALLOW IN  Anywhere (v6)
[ 3] 443/tcp  ALLOW IN  Anywhere        [ 6] 443/tcp (v6)  ALLOW IN  Anywhere (v6)
```

`/etc/default/ufw`: `DEFAULT_FORWARD_POLICY="ACCEPT"`.

Замер снаружи после `ufw` (тот же инструмент, что и в §2):

| Порт | Ожидание | Факт |
| --- | --- | --- |
| 22 | доступен | `OPEN (слушает)` |
| 80, 443 | проходят на хост, слушателя ещё нет (Caddy появится в T-713) | `REACHABLE, слушателя нет (RST)` |
| 5432, 8080, 9101, 10800 | закрыты | `FILTERED (пакеты теряются)` |

SOCKS-вход туннеля (`127.0.0.1:10800`) наружу не смотрит и дополнительно отфильтрован `ufw`.

## 4. Шаг 3 — fail2ban: учение с реальными пробами

Артефакт: `deploy/vps/fail2ban-jail.local` → на площадке `/etc/fail2ban/jail.d/tbot.local`
(`backend = systemd`, 3 неудачи за 10 минут → бан 30 минут, рост до 24 ч, `ignoreip` — loopback
и приватные сети; публичный адрес рабочей станции в исключения **не** внесён).

Проверка механизма без риска для собственного входа — бан адреса из TEST-NET (RFC 5737):

```
$ sudo fail2ban-client set sshd banip 203.0.113.77
Banned IP list: 203.0.113.77
$ sudo nft -a list ruleset | grep -iE "fail2ban|203.0.113.77"
		elements = { 203.0.113.77 }
```

В Ubuntu 24.04 `fail2ban` 1.0.2 работает через действие `nftables` (`fail2ban-client get sshd
actions` → `nftables`), бана в `iptables -S` нет — это не поломка, а способ реализации; проверять
надо `nft list ruleset`, а не `iptables -S`.

Учение целиком (критерий T-708 «fail2ban баннит пробы; SSH-доступ не потерян»):

1. на хосте вооружён автоматический разбан: `systemd-run --on-active=75s` и `--on-active=240s`
   (страховка от потери доступа, снимается `systemctl stop <timer>`);
2. с рабочей машины сделано 5 попыток входа заведомо неверным способом
   (`tbotprobe@…`, `PubkeyAuthentication=no`, `BatchMode=yes`) → `Permission denied (publickey)`;
3. сразу после этого SSH с той же машины: `connect to host 153.51.172.30 port 22: Connection
   timed out` — источник забанен, пакеты теряются (не `refused`, что соответствует DROP-действию);
4. после срабатывания таймера разбана: `SSH_ВОССТАНОВЛЕН`, `Currently banned: 0`,
   `Total banned: 3` (наш тест плюс две пробы сканеров из интернета — то есть бан реагирует на
   реальный фоновый шум).

## 5. Шаг 4 — Docker Engine и compose (часть T-712)

Пакеты **дистрибутива**, не `get.docker.com`: `docker.io 29.1.3-0ubuntu3~24.04.2`,
`docker-compose-v2 2.40.3+ds1-0ubuntu1~24.04.1`, `containerd 2.2.1`. Юнит `docker` —
`active` + `enabled`. Команда — `docker compose` (не `docker-compose`).

Отличие от плана задачи: в задачах и в TZ фигурировало имя `docker-compose-plugin` — это имя
пакета вендорного Docker CE. В репозитариях Ubuntu 24.04 compose v2 называется
**`docker-compose-v2`** (`apt-cache policy docker-compose-plugin` → «Unable to locate package»,
кандидат `docker-compose-v2 2.40.3+ds1-0ubuntu1~24.04.1`). Смысл требования TZ §14.4
«пакеты из репозиториев дистрибутива» выполнен точно.

`/etc/docker/daemon.json` — из `deploy/vps/docker-daemon.json`: `json-file` с
`max-size=50m`/`max-file=10` (TZ §14.6) и пул сетей `172.28.0.0/16` вне адресного пространства ВМ.

Smoke-проверки на площадке (подтверждают, что настройки безопасности из compose.yaml реально
применимы к локальному Docker):

| Проверка | Результат |
| --- | --- |
| `--read-only` | `touch: /etc/x: Read-only file system` |
| `--security-opt no-new-privileges:true` | `NoNewPrivs: 1` |
| `--cap-drop ALL` | `CapEff: 0000000000000000` |
| `--network none` | интерфейсы контейнера: только `lo` |
| egress контейнера через bridge | `https://ghcr.io/v2/` → `HTTP/1.1 401 Unauthorized` |
| DNS в контейнере | резолвер `10.130.0.2` (внутренний резолвер Yandex Cloud) |

Два наблюдения, важных для эксплуатации:

- **`FORWARD` policy = DROP — не мешает контейнерам.** Docker 29 не меняет политику `FORWARD`
  (`-P FORWARD DROP`) и вставляет свои цепочки первыми:
  `-A FORWARD -j DOCKER-USER`, `-A FORWARD -j DOCKER-FORWARD`. Исходящий трафик контейнеров
  работает через них, а не через политику цепочки. `DEFAULT_FORWARD_POLICY="ACCEPT"` в
  `/etc/default/ufw` оставлен как явное намерение (и нужен, если появится сквозной routing), но
  выключать его из-за «и так работает» не стоит: вывод `ufw status` по-прежнему показывает
  `disabled (routed)`, то есть сам ufw политикой пересылки не управляет.
- **Доверие НУЦ не наследуется из хоста в контейнер.** Тот же запрос к
  `invest-public-api.tbank.ru` из `alpine:3.20` даёт `certificate verify failed`, хотя на хосте
  цепочка доверена (T-709). Это подтверждает требование `docs/acceptance/broker-tls.md`: корень
  обязан лежать в образе (`deploy/Dockerfile`), а не только на площадке.

## 6. Откат

| Действие | Команда на площадке |
| --- | --- |
| выключить `ufw` (правила сохраняются) | `sudo ufw disable` |
| снять конкретное правило | `sudo ufw status numbered` → `sudo ufw delete <номер>` |
| размбанить адрес | `sudo fail2ban-client set sshd unbanip <адрес>` |
| остановить Docker без удаления данных | `sudo systemctl stop docker` |
| удалить образы/контейнеры, оставив том БД | `sudo docker system prune -f` (том `pgdata` не трогает) |

## 7. Границы приёмки (что этим протоколом НЕ принято)

1. **T-712 целиком не принят**: pull образов приложений по digest не выполнен — нет read-only
   токена GHCR на площадке (`/etc/tbot/secrets/ghcr_token`, см. `docs/runbook/ghcr-pull.md §3`).
   Проверена только доступность `ghcr.io/v2/` (`401` без авторизации) и дайджесты публичного
   `postgres:16.4`.
2. Секретов приложения (`db_password`, `db_url`, `tg_bot_token`) на площадке нет, каталог
   `/etc/tbot/secrets` существует с правами `750 root:root`.
3. `caddy` и сертификат Let's Encrypt — T-713; пока 80/443 проходят на хост, но слушать нечего.
4. Egress-политика контейнеров (TZ §8.5: «разрешены только адреса брокера, Telegram-канала и
   репозитория») — отдельная работа в цепочке `DOCKER-USER`; сейчас контейнер ходит наружу
   по любому адресу.
5. Мониторинг и бэкапы (TZ §14.7 шаг 3) — до первого боевого запуска; схема выбрана
   (`docs/adr/ADR-002`, TZ §14.10), реализация — T-702.

## 8. Как повторить проверки

```bash
# состояние файрвола и юнитов
ssh rusiksoft@153.51.172.30 'sudo ufw status numbered; systemctl is-active ufw docker fail2ban'
# снаружи (с рабочей машины)
for p in 22 80 443 5432 8080 9101 10800; do printf "%-6s " $p; \
  timeout 6 bash -c "</dev/tcp/153.51.172.30/$p" 2>/dev/null && echo OPEN || \
  { timeout 6 bash -c "</dev/tcp/153.51.172.30/$p" 2>&1 | grep -qi refused \
    && echo "REACHABLE, слушателя нет" || echo "FILTERED"; }; done
# fail2ban: бан тестового адреса и проверка в nftables, затем размбан
ssh rusiksoft@153.51.172.30 'sudo fail2ban-client set sshd banip 203.0.113.77; \
  sudo nft list ruleset | grep -c "203.0.113.77"; sudo fail2ban-client set sshd unbanip 203.0.113.77'
# hardening-дым: read-only, без привилегий, без capability, без сети
ssh rusiksoft@153.51.172.30 'sudo docker run --rm --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --network none alpine:3.20 sh -c \
  "grep -E \"NoNewPrivs|CapEff\" /proc/self/status; ls /sys/class/net"'
```
