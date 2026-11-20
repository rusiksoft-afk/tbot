# Runbook: образы из GHCR по digest (T-712, TZ §14.6)

Образы приложений публикуются workflow `Image` в `ghcr.io/rusiksoft-afk/tbot-{web,tgbot,engine,jobs}`.
Репозиторий приватный: без токена GHCR отвечает `401` (проверено с рабочей ВМ: `https://ghcr.io/v2/`
→ `verify=0 http=401`, то есть TLS работает, а авторизации нет).

## 1. Почему деплой идёт по digest, а не по тегу

Тег `main` — перемещаемая метка: два разных деплоя «по `main`» могут собрать разные наборы
слоёв, и «откат на previous» тогда не воспроизводится. Digest (`sha256:…`) — имя конкретного
манифеста; он не меняется, пока не изменён сам образ. Откат = поднять прежний digest
(TZ §12.7, учение «деплой предыдущей версии и откат»).

Теги, которые публикует workflow: `sha-<короткий commit>` (для людей) и `main` (для «свежего»).
В деплое используется только `@sha256:…`.

## 2. Где брать дайджесты

Из прогона workflow `Image` (не из UI GHCR — там дайджест показан для каждой метки отдельно):

```bash
gh run list  --repo rusiksoft-afk/tbot --workflow image.yml --limit 5
gh run view <run-id> --repo rusiksoft-afk/tbot --log 2>/dev/null \
  | sed -E 's/\x1b\[[0-9;]*m//g' \
  | grep -oE "pushing manifest for ghcr\.io/rusiksoft-afk/tbot-[a-z]+:main@sha256:[0-9a-f]{64}" \
  | sed -E 's/pushing manifest for //' | sort -u
```

Состояние на 2026-11-20 13:12 MSK (commit `b235d29` — мерж PR #2, run `44716926556`):

| Образ | Тег | Digest |
| --- | --- | --- |
| `ghcr.io/rusiksoft-afk/tbot-web` | `main`, `sha-b235d29` | `sha256:0f48265114538fbc60aa407cefb9b183f6fa29aa868d2d7590c54eaaea5f970d` |
| `ghcr.io/rusiksoft-afk/tbot-tgbot` | `main`, `sha-b235d29` | `sha256:873152b3a9178290736f0676ed253817b52702c1db60bd1f788ac4ac6db2e37e` |
| `ghcr.io/rusiksoft-afk/tbot-engine` | `main`, `sha-b235d29` | `sha256:c5c1af5e451db1ddf4b7e1d7efed8accf6fac23fb4e7bed564de069670006e03` |
| `ghcr.io/rusiksoft-afk/tbot-jobs` | `main`, `sha-b235d29` | `sha256:04070e40b269dce3ed264b131d98cedac5d1c0fca2f1e0cc868f75f3c702753f` |
| `postgres` (публичный, Docker Hub) | `16.4` | `sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412` |
| `caddy` (публичный, Docker Hub) | `2` (v2.11.9) | `sha256:4851e54a46b206517c574821bb5cc67f170d2156041e9fbc4c9193b45e84a75b` |

Предыдущие наборы — точки отката по TZ §12.7. Commit `21579ba`, run `44708907667`: web
`sha256:c33283cf…970d`, tgbot `sha256:413b1df8…637e`, engine `sha256:ae6faf72…3914`, jobs
`sha256:a8800433…753f`. Commit `4fa1b51`, run `44689994900`: web `sha256:5705a7ba…5fdc`,
tgbot `sha256:5d009e00…1a19`, engine `sha256:b0740c89…6b21`, jobs `sha256:9adee970…32a3`.
Полные значения — в истории git по сообщению «дайджесты образов пересняты»; именно поэтому файл
`deploy/tbot.prod.env` обязан обновляться **одним** коммитом вместе с номером commit и номером
прогона.

**Сборка не воспроизводима по digest.** Два прогона одного и того же кода дают разные манифесты
(метки времени слоёв): набор меняется после каждого мержа в `main` — даже если `apps/`,
`packages/`, `deploy/Dockerfile` и `pyproject.toml` не менялись вовсе (проверено 2026-11-20:
наборы `21579ba` и `b235d29` различаются при неизменном коде приложения). Отсюда правило, которое
снимает бесконечную гонку: пересъёмка делается **непосредственно перед деплоем**, а деплоится тот
коммит, чей набор записан в файле. Соответствие проверяется по паре «run → commit» из заголовка
файла: дайджесты обязаны существовать в реестре и быть выложенными в указанном прогоне, но
совпадать с дайджестами самого свежего прогона они не обязаны. Сам коммит пересъёмки запускает
`Image` и порождает следующий набор — это ожидаемо и очередной пересъёмки не требует.

`postgres` берётся не из GHCR, но тоже пинится по digest: сборка CI и площадка должны получать
один и тот же образ базы, иначе «учение на площадке» проверяет не ту версию, что в CI. Проверка
на площадке: `sudo docker image inspect postgres:16.4 --format "digests={{.RepoDigests}}"`.

## 3. Read-only токен: размещение (решение заказчика от 2026-11-20)

Токен — **файл-секрет** на площадке, не переменная окружения и не параметр команды:

1. На GitHub создаётся **fine-grained personal access token** владельца/организации `rusiksoft-afk`:
   Only repositories → `tbot`; permissions: **Contents: Read-only**, **Packages: Read-only**.
   Больше прав не нужно (pull не пишет ни в packages, ни в metadata).
2. На рабочей ВМ создаётся каталог с правильными правами:

   ```bash
   ssh -i ~/.ssh/tbot/ssh-key-1795095923419 rusiksoft@153.51.172.30 \
     'sudo install -d -m 750 -o root -g root /etc/tbot/secrets'
   ```

3. Значение вводится **локально, без эха**, и уходит на ВМ по stdin того же SSH-канала — так
   токен не попадает в чат, в аргументы команды (`ps`), в `.bash_history` и в логи CI:

   ```bash
   read -rs -p "GHCR read-only token: " TOK && printf '%s' "$TOK" | ssh \
     -i ~/.ssh/tbot/ssh-key-1795095923419 rusiksoft@153.51.172.30 \
     'sudo umask 077 && sudo tee /etc/tbot/secrets/ghcr_token >/dev/null' && unset TOK
   ```

4. Проверка прав (вывод не содержит значения):

   ```bash
   ssh -i ~/.ssh/tbot/ssh-key-1795095923419 rusiksoft@153.51.172.30 \
     'sudo ls -l /etc/tbot/secrets; sudo stat -c "%a %U:%G %n" /etc/tbot/secrets/ghcr_token; sudo wc -c /etc/tbot/secrets/ghcr_token'
   ```

   Ожидается `-rw------- 1 root root` (600) и длина токена (fine-grained `github_pat_…` — 93 байта).
   Файл без завершающего перевода строки: `docker login --password-stdin` воспринимает перевод
   строки как часть секрета.

Чего не должно быть: `docker login -p <токен>` (виден в `ps`), `echo <токен> > file` (виден в
истории), `docker run -e GITHUB_TOKEN=…`, коммит в репозиторий, значение в логе CI. Проверка
репозитория на утечку — job `поиск секретов (gitleaks)`; проверка площадки — `sudo grep -r
"ghcr" /etc/systemd/system /etc/docker 2>/dev/null` (в юнитах и daemon.json токена быть не должно).

## 4. Вход и загрузка по digest

```bash
ssh -i ~/.ssh/tbot/ssh-key-1795095923419 rusiksoft@153.51.172.30 '
  sudo docker login ghcr.io --username <логин-владельца-токена> \
    --password-stdin < /etc/tbot/secrets/ghcr_token
  sudo docker pull ghcr.io/rusiksoft-afk/tbot-web@sha256:5705a7baf471c5f16ae8035774a600f2966e63e410b7ebc3725d19610d5f5fdc
  sudo docker pull ghcr.io/rusiksoft-afk/tbot-engine@sha256:b0740c89ae501ee4a6ad2940976e8fdad0e40b2214a37fe0361c407f57406b21
  sudo docker pull ghcr.io/rusiksoft-afk/tbot-jobs@sha256:9adee970b314c4aed3b113137d26f9c8280a483b13e9e00cbd964b6770f832a3
  sudo docker pull ghcr.io/rusiksoft-afk/tbot-tgbot@sha256:5d009e000b0fdc98732c37e969037dd775b99c8ad256e7a2cd7c04193dcc1a19
  sudo docker pull postgres@sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412
  sudo docker image inspect --format "{{.Id}} {{.RepoDigests}}" \
    ghcr.io/rusiksoft-afk/tbot-web@sha256:5705a7baf471c5f16ae8035774a600f2966e63e410b7ebc3725d19610d5f5fdc'
```

`docker login` пишет только `Login Succeeded` (имя пользователя не секрет). Вывод `docker pull`
содержит только digest — это ожидаемо и безопасно для логов.

## 5. Деплой и откат

```bash
# деплой конкретного набора
cd /opt/tbot && sudo docker compose -f deploy/compose.yaml -f deploy/compose.prod.yaml \
  --env-file deploy/tbot.prod.env config          # проверка, что дайджесты подставились
... up -d && ... run --rm migrate alembic upgrade head
# откат: тот же compose, но в deploy/tbot.prod.env предыдущие digest из прошлого релиза
```

Учение по TZ §12.7: поднять предыдущий digest, убедиться, что `/readyz` зелёный, затем миг
вперёд обратно. Миграции обязаны быть совместимы с прежним образом (шаг миграции — отдельный
прогон `migrate`, downgrade только если явно разрешено).

## 6. Что сейчас заблокировано

- Токена на площадке **нет**: в `/etc/tbot/secrets` лежат только `telegram_socks_user`/
  `telegram_socks_pass`. Пока он не размещён, pull образов приложений проверить нельзя
  (`ghcr.io/v2/` → 401), поэтому половина приёмки T-712 («pull по digest») не принята.
- Секретов приложения (`db_password`, `db_url`, `tg_bot_token`) на площадке тоже нет — их кладёт
  заказчик теми же файлами `600` (процедура токена Telegram — `docs/runbook/telegram-token.md`).
- Боевой `compose.prod.yaml` ещё не написан: он появляется вместе с Caddy (T-713), потому что
  единственный публикуемый наружу порт — 80/443 самого Caddy.
