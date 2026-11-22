# Runbook: образы из GHCR по digest (T-712, TZ §14.6)

Образы приложений публикуются workflow `Image` в `ghcr.io/rusiksoft-afk/tbot-{web,tgbot,engine,jobs}`.
Репозиторий с 2026-11-22 **публичный** (`docs/adr/ADR-019`), но **пакеты образов остались
приватными**: без токена GHCR отвечает `401` (проверено с рабочей ВМ: `https://ghcr.io/v2/`
→ `verify=0 http=401`, то есть TLS работает, а авторизации нет; контрольный зонд 2026-11-22 —
анонимный `GET /token?scope=repository:rusiksoft-afk/tbot-web:pull` даёт `401`, тогда как
анонимный же запрос для публичного образа отвечает `200`). Поэтому `ghcr_token` на площадке
нужен, а порядок `pull` ниже не меняется.

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

Состояние на 2026-11-20 13:46 MSK (последний зелёный `Image` перед деплоем — commit
`1ce4be6`, run `44721673799`):

| Образ | Тег | Digest |
| --- | --- | --- |
| `ghcr.io/rusiksoft-afk/tbot-web` | `main`, `sha-1ce4be6` | `sha256:4aa09b13224e4f82031281ef4db460e66c428b9c566128d19004111f5cfae7e6` |
| `ghcr.io/rusiksoft-afk/tbot-tgbot` | `main`, `sha-1ce4be6` | `sha256:e9993ac68693c9e2afe6f3dc85d2f5ab8119352ad53365d6bcacca90b5a635f1` |
| `ghcr.io/rusiksoft-afk/tbot-engine` | `main`, `sha-1ce4be6` | `sha256:422818369c3f96731aa1c5b7054d5b94a65ef4b3032ed976de0fb12dae2f93fa` |
| `ghcr.io/rusiksoft-afk/tbot-jobs` | `main`, `sha-1ce4be6` | `sha256:14b72e92a9fe5e89b5a7e2ca17fe5f24015427502cda5927a427e69c04865157` |
| `postgres` (публичный, Docker Hub) | `16.4` | `sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412` |
| `caddy` (публичный, Docker Hub) | `2` (v2.11.9) | `sha256:4851e54a46b206517c574821bb5cc67f170d2156041e9fbc4c9193b45e84a75b` |

Предыдущие наборы — точки отката по TZ §12.7. Commit `b235d29`, run `44716926556`: web
`sha256:0f482651…970d`, tgbot `sha256:873152b3…637e`, engine
`sha256:c5c1af5e…6e03`, jobs `sha256:04070e40…753f`. Commit `21579ba`,
run `44708907667`: web
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
     'sudo install -d -m 700 -o root -g root /etc/tbot/secrets'

   Режим каталога — `700`. На замере 2026-11-20 каталог был `750` (его создавала настройка
   туннеля Telegram), и `--check` на это жалуется `WARN`; скрипт ввода секретов сам делает
   `install -d -m 700`, так что отдельная команда не обязательна.
   ```

3. Значение вводится **без эха** и уходит на ВМ по stdin того же SSH-канала — так токен
   не попадает в чат, в аргументы команды (`ps`), в `.bash_history` и в логи CI. Единственный
   правильный получатель значения — `deploy/vps/secrets-setup.sh`: он проверяет форму **до**
   записи, ставит `600 root:root` и пишет без завершающего `\n` (см. ниже два
   варианта):

   ```bash
   # вариант 1: значение с клавиатуры на самой ВМ (ввод без эха)
   sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --only ghcr_token

   # вариант 2: значение вводится на dev-машине и проливается в stdin скрипта по SSH-каналу
   read -rs -p "GHCR read-only token: " TOK
   printf '%s' "$TOK" | ssh -i ~/.ssh/tbot/ssh-key-1795095923419 rusiksoft@153.51.172.30 \
     'sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --force --only ghcr_token'
   unset TOK
   ```

   `--force` во втором варианте обязателен: прогон не интерактивный (без терминала скрипт
   писать не станет), и перезатирать уже лежащий мусор придётся без вопроса. После записи —
   `sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check`, ожидание: пять `OK` и код 0.
   Прежний рецепт с `sudo tee` устарел с 2026-11-20: он пишет любое значение без проверки
   формы — именно так в файл и попали 11 символов не-PAT.

### Зелёный `--check` не означает, что токен рабочий: функциональная проба

Замер 2026-11-20 15:29 UTC: `ghcr_token` размещён (93 байта, `600 root:root`, форма
`github_pat_…`), `secrets-setup.sh --check` — **пять** `OK` и код 0. При этом тот же файл даёт:

| проба (значение читается внутри процесса на ВМ, в `argv` не попадает) | ответ |
| --- | --- |
| `GET https://api.github.com/user` | `200`, `login=rusiksoft-afk`, `type=User` (личный аккаунт, не организация) |
| `GET /repos/rusiksoft-afk/tbot/contents/deploy` | `404` — репозиторий не в области видимости токена |
| `GET /user/packages?package_type=container` | `403` «Resource not accessible by personal access token» — право Packages не выдано |
| `GET ghcr.io/token?service=ghcr.io&scope=repository:rusiksoft-afk/tbot-web:pull` с Basic | `200` (обмен проходит) |
| `GET ghcr.io/v2/.../tags/list` и `manifests/main` с выданным JWT | `403` |
| `GET ghcr.io/v2/.../manifests/<digest из deploy/tbot.prod.env>` | `404` |

Вывод: проверка формы в скрипте отвечает только за «файл не мусор». Права токена проверяются
обращением к реестру, и делать это надо **до** `pull`: иначе `pull` падает на
`denied`/`unauthorized` уже после того, как скачана половина слоёв. Отдельная грабля: правильная
форма обмена — Basic (`-u логин:токен`), а не `Bearer`; с `Bearer` GHCR отвечает `401` даже на
валидном токене (тот же замер: `exchange=401`, при этом `GET /user` тем же токеном — `200`).

Проба, которая ничего не печатает кроме вердиктов (значение читается внутри процесса под `sudo`):

```bash
ssh -i ~/.ssh/tbot/ssh-key-1795095923419 rusiksoft@153.51.172.30 'sudo python3 -' <<'PROBE'
import base64, json, urllib.request, urllib.error
tok = open('/etc/tbot/secrets/ghcr_token', 'rb').read().strip().decode()
basic = base64.b64encode(('rusiksoft-afk:' + tok).encode()).decode()
def req(url, headers=None):
    r = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=25) as f:
            return f.status, f.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()
gh = {'Authorization': 'Bearer ' + tok, 'Accept': 'application/vnd.github+json'}
st, body = req('https://api.github.com/user', gh)
d = json.loads(body or b'{}')
print('login=%s id=%s type=%s http=%s' % (d.get('login'), d.get('id'), d.get('type'), st))
st, _ = req('https://api.github.com/user/packages?package_type=container', gh)
print('packages-list http=%s (нужно 200; 403 = нет права Packages)' % st)
stx, bx = req('https://ghcr.io/token?service=ghcr.io&scope=repository:rusiksoft-afk/tbot-web:pull',
              {'Authorization': 'Basic ' + basic})
jwt = json.loads(bx or b'{}').get('token', '')
acc = {'Authorization': 'Bearer ' + jwt,
       'Accept': 'application/vnd.oci.image.index.v1+json,'
                 'application/vnd.docker.distribution.manifest.list.v2+json,'
                 'application/vnd.docker.distribution.manifest.v2+json'}
st, _ = req('https://ghcr.io/v2/rusiksoft-afk/tbot-web/manifests/main', acc)
print('exchange http=%s jwt_len=%s manifest(main) http=%s' % (stx, len(jwt), st))
PROBE
```

Ожидание на рабочей площадке: `packages-list http=200` и `manifest(main) http=200`. Если
`packages-list` отвечает `403`, а обмен — `200`, у токена нет `Packages: Read-only`: право
выдаётся в настройках fine-grained токена (Repository access → `tbot`, Permissions →
Contents: Read-only + Packages: Read-only), либо ставится классический PAT только со
`read:packages` (скрипт его тоже принимает: `gh[pousr]_[A-Za-z0-9]{36,}`). Значения при этом по
прежнему вводит заказчик (ADR-004, режим 1 или 3) — проба нужна только для вердикта.

### Кому принадлежит токен: как узнать логин, не поднимая токен в argv

Логин нужен для `sudo docker login ghcr.io --username <логин> --password-stdin`. Заказчик
предложил выяснять его на площадке запросом `GET /user`, но в такой форме токен уходит в
аргументы процесса: `-H "Authorization: Bearer $(cat /etc/tbot/secrets/ghcr_token)"` видно в
`ps` любому локальному пользователю в момент вызова. Форма ниже читает файл внутри процесса и
не показывает значение:

```bash
ssh -i ~/.ssh/tbot/ssh-key-1795095923419 rusiksoft@153.51.172.30 \
  'sudo python3 - <<PY
import json, urllib.request, urllib.error
tok = open("/etc/tbot/secrets/ghcr_token").read().strip()
req = urllib.request.Request("https://api.github.com/user",
                             headers={"Authorization": "Bearer " + tok,
                                      "User-Agent": "tbot-deploy"})
try:
    with urllib.request.urlopen(req) as r:
        print("login:", json.load(r).get("login"))
except urllib.error.HTTPError as e:
    print("HTTP", e.code, e.reason)
PY'
```

Ограничение, которое нельзя забыть: `GET /user` отвечает классическим токеном. У
fine-grained PAT этот эндпоинт может ответить `403`, и тогда логин либо сообщается владельцем
токена, либо берётся из ответа на `GET /rate_limit` — у fine-grained токена GitHub отдаёт
служебный заголовок владельца. Проверять надо по факту, а не по догадке: на замере 2026-11-20
у классического OAuth-токена `gh` таких заголовков нет (есть `x-oauth-scopes`), поэтому
инструкция фиксируется как проба, а не как гарантированный способ.

Есть и более прямой тест готовности — не «чей токен», а «тянет ли он образ»: обмен в
`https://ghcr.io/token?scope=repository:rusiksoft-afk/tbot-web:pull` и GET манифеста по digest.
Если манифест отдаётся, pull на площадке пройдёт независимо от того, какой логин показало API.

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
