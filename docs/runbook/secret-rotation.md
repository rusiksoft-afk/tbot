# Ротация учётных данных и ключей

Ранбук отвечает на вопрос «как поменять значение, не показав его». Он же закрывает ловушки,
которые 2026-11-22 стоили по прогону. Основание — `docs/adr/ADR-004` (кто вносит значения),
`ADR-005` (права файлов), `ADR-019` (почему ротация потребовалась: репозиторий стал публичным,
а документы с адресами, пользователем `rusiksoft` и именем деплой-ключа стали публичными).

## 1. Кто что ротирует

| Значение | Кто ротирует | Чем |
|---|---|---|
| `db_password`, собираемый из него `db_url` | агент (режим 2 `ADR-004`: значение машиногенерируемое) | `deploy/vps/secrets-setup.sh --only db_password db_url --force` + `ALTER ROLE` (§3) |
| SSH deploy-ключ клона `/opt/tbot` | агент (значения генерируются на ВМ) | `ssh-keygen` + GitHub API, read-only (§4) |
| `telegram_token` | **только заказчик** (режим 1 `ADR-004`) | `@BotFather` + `secrets-setup.sh --only telegram_token` (§5) |
| `ghcr_token` | **только заказчик** (режим 1 `ADR-004`) | GitHub → tokens + `secrets-setup.sh --only ghcr_token` (§5) |
| `telegram_socks_pass` | вне этого ранбука | относится к узлу B `176.32.39.234` (стоп-лист `AGENTS.md`), меняется только вместе с `/etc/tbot-tunnel/config.json` по отдельному разрешению |

Инвариант на все пункты: значение не попадает в `stdout`, `argv` (`ps`), stderr, чат, историю
оболочки и логи. Отсюда запрет на `curl -H "Bearer $(cat f)"`, на `-e КЛЮЧ=значение` и на `sed`
по файлам секретов.

## 2. Порядок и запреты

1. До изменения — замеры: `secrets-setup.sh --check` (имена, размеры, права, форма), состояние
   контура (`docker ps`, `/readyz`), отпечатки проверяемых объектов. Отпечатки (первые 12
   знаков sha256, отпечатки ssh-ключей) — безопасная метрика «значение изменилось»; сами
   значения не печатаются.
2. Значение пишет **только** `deploy/vps/secrets-setup.sh` (права ставит сам: монтируемые
   составом — `640 root:gid10001`, хозяйский `ghcr_token` — `600 root:root`; `--remed` приводит
   права без смены значения).
3. После записи — `--check` обязателен зелёным, затем поведенческие проверки (не «файл изменился»,
   а «путь работает»: `/readyz`, `alembic current`, `ls-remote`).
4. Боевой кластер не засоряется: временных БД и ролей не создавать, дампы перед ротацией не
   снимать (шифрование дампов — `T-702`, ещё не реализовано).
5. Откат значения — **не** прежнее: прежнее значение после записи восстановить нельзя (скрипт
   пишет файл усечением по месту, бэкапа значений нет). Откат = повторная ротация вперёд. Это
   причина, по которой ротацию нельзя делать «на автомате» вне плана.

## 3. `db_password` и `db_url` (роль приложения и роль-мигратор)

Порядок — «значение в файл → пароль в обе роли → перезапуск приложения»: перезапуск раньше ALTER
даёт `password authentication failed for user "tbot_app"` (замерено 2026-11-22: между шагами
`/readyz` отвечал 503, `web` — `health: starting`).

```bash
COMPOSE='sudo docker compose -f /opt/tbot/deploy/compose.yaml -f /opt/tbot/deploy/compose.prod.yaml --env-file /opt/tbot/deploy/tbot.prod.env'

# 1) новое значение генерируется вне argv и уходит в скрипт по stdin (скрытый read в скрипте)
new=$(openssl rand -hex 24)
printf '%s\n' "$new" | sudo TBOT_DB_USER=tbot_app \
  bash /opt/tbot/deploy/vps/secrets-setup.sh --only db_password db_url --force
unset new
sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check
```

`TBOT_DB_USER=tbot_app` обязателен: дефолт скрипта — `tbot`, без него `db_url` молча соберётся
под ролью-владельцем и приложение потеряет доступ (роль-мигратор — отдельная переменная
`TBOT_MIGRATION_DB_USER`, `ADR-018`).

Команды ALTER и проверки верификаторов — `docs/runbook/postgres-roles.md` §5 (там же разбор
`printf %L`). Кратко: `ALTER ROLE tbot_app PASSWORD …; ALTER ROLE tbot_app LOGIN; ALTER ROLE tbot
PASSWORD …;` одним потоком по stdin в `psql` контейнера `postgres`, SQL-файл 600 `root:root` и
`shred -u` сразу после.

Проверки после ротации (замер 2026-11-22, всё зелёное):

```bash
$COMPOSE restart web            # engine/jobs/tgbot не трогать: они не входят в задеплоенный контур
$COMPOSE exec -T web python -c "…current_user…"    # → tbot_app, superuser=false, users=0, 0004
$COMPOSE run --rm -T migrate alembic current < /dev/null   # → «0004 (head)», rc=0: роль-мигратор под новым паролем
sudo cat /opt/tbot/deploy/postgres/roles.sql | $COMPOSE exec -T postgres psql -q -X -v ON_ERROR_STOP=1 -U tbot -d tbot
```

`roles.sql` переприменяется ролью-владельцем: `sudo cat` обязателен, потому что `< файл` в
redirection читает оболочка от имени `rusiksoft`, а каталог `/opt/tbot` — `750 root:root`
(замер: `Permission denied`, при этом код возврата конвейера нулевой — ловушка).

## 4. SSH deploy-ключ клона `/opt/tbot`

Порядок: новый ключ → проверка → добавление → проверка с ВМ при активном старом → отзыв старого
→ повторная проверка (новый работает, старый отказывает). Обратный порядок рвёт канал клона.

```bash
# на ВМ
sudo ssh-keygen -q -t ed25519 -a 100 -N '' -C 'tbot-deploy-key-<дата>/rotation' \
  -f /root/.ssh/tbot_deploy_key_<дата>
sudo cat /root/.ssh/tbot_deploy_key_<дата>.pub      # публичная часть — не секрет
sudo ssh-keygen -lf /root/.ssh/tbot_deploy_key_<дата>.pub   # отпечаток для приёмки

# с рабочей машины (read_only=true обязателен: ключ не даёт писать в репозиторий)
gh api -X POST repos/rusiksoft-afk/tbot/keys -f title='prod-vm-tbot-<дата>' \
  -f key="<публичная часть>" -F read_only=true --jq '{id,title,read_only}'
gh api repos/rusiksoft-afk/tbot/keys --jq '.[] | {id,title,read_only}'

# с ВМ: проба новым ключом, старый ещё активен
sudo git -C /opt/tbot -c core.sshCommand="ssh -o IdentitiesOnly=yes -i /root/.ssh/tbot_deploy_key_<дата>" ls-remote origin HEAD

# отзыв старого (id из предыдущего списка)
gh api -X DELETE repos/rusiksoft-afk/tbot/keys/<старый_id>

# доказательство: старый ключ обязан отказать, новый обязан ответить
sudo git -C /opt/tbot -c core.sshCommand="ssh -o IdentitiesOnly=yes -i /root/.ssh/tbot_deploy_key" ls-remote origin HEAD   # Permission denied (publickey)
sudo git -C /opt/tbot -c core.sshCommand="ssh -o IdentitiesOnly=yes -i /root/.ssh/tbot_deploy_key_<дата>" ls-remote origin HEAD
sudo mv /root/.ssh/tbot_deploy_key /root/.ssh/tbot_deploy_key.revoked-<дата>
sudo mv /root/.ssh/tbot_deploy_key.pub /root/.ssh/tbot_deploy_key.pub.revoked-<дата>
```

`ls-remote` — правильная проверка: она проверяет аутентификацию, не меняя клон. `pull` на
площадке при ротации **не выполняется**: клон обязан оставаться на задеплоенном срезе, иначе
расходится связь «работающий набор образов ↔ `deploy/tbot.prod.env`» (см. `stand-deploy §2–3`).

## 5. Внешние токены — только заказчик

Значения создаёт и вводит только заказчик (`ADR-004` режим 1); агент не видит содержимого и не
может влить значение в stdin чужого токена. Порядок для заказчика:

1. Отозвать прежний токен (`@BotFather` → `/revoke` для `telegram_token`; GitHub →developer
   settings → personal access tokens → revoke для `ghcr_token`) и создать новый.
2. Ввести значение интерактивно, со скрытым вводом и подтверждением перезаписи:
   `ssh -t -i ~/.ssh/tbot/ssh-key-… rusiksoft@153.51.172.30 'sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --only ghcr_token telegram_token'`
   (ключ `-t` даёт терминал; без него скрипт под sudo не пишет файлы — нужен был бы `--force`).
3. Проверить: `sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check`.
4. Для `ghcr_token` — перелогин на ВМ (`docs/runbook/ghcr-pull.md` §3: форма с `sudo sh -c`,
   токен по stdin, не в argv) и проверка `pull` по digest.
5. `telegram_token` меняется без перезапуска `web` (его читает `tgbot`, который не поднят); при
   подъёме `tgbot` файл читается при старте.

## 6. Ловушки, разобранные 2026-11-22

- **Пустой ввод скрипта не перегенерирует значение.** `secrets-setup.sh` при пустой строке
  оставляет существующее значение, если оно проходит проверку формы: вывод
  `db_password: оставлен существующий (48 байт)` при `--force`. Генерация «на пустом вводе»
  работает только когда значения ещё нет. Значит ротация требует явного нового значения на stdin
  (§3) или удаления файла перед запуском — второе оставляет окно без файла и без отката.
- **`printf %L` в контейнере `postgres` не работает** (`sh` — dash): `invalid directive`, обрывок
  SQL, `syntax error at end of input`, нулевой код возврата конвейера. Подробности и рабочая
  форма — `postgres-roles.md` §5.
- **Вложенные кавычки в `sudo sh -c '… "$p" …'` раскрывает внешний bash.** При `set -u` это
  `p: unbound variable`, без него — подстановка пустой строки. Проверять форму значения нужно
  внутри root-команды (python-скрипт, читающий файл секрета), а не в строке, которую пишет
  непривилегированная оболочка.
- **`sha256()` в Postgres отдаёт `bytea`**: `left(sha256(...),12)` падает, нужен
  `encode(…,'hex')`.
- **`docker compose run`/`exec` читает stdin** и съедает остаток `bash -s`-скрипта: у `run` —
  `< /dev/null`, код возврата `migrate` читать без конвейера (`| tail` даёт код `tail`).

## 7. Что остаётся незакрытым

- Ротация KEK-файла (`/etc/tbot/keys/kek.json`) — задача `T-107`, отдельная процедура: версия KEK
  внутри `secret_enc` (`ADR-014`), перешифрование привязок, а не замена файла.
- Ротация `telegram_socks_pass` — только вместе с узлом B, вне этого ранбука.
- Дамп/бэкап файлов секретов и KEK — `T-702`; без него откат значения невозможен в принципе.
- Автоматизации ротации по сроку нет (`scripts/dev.py` её не заводит осознанно): журнал ротации и
  обязательный бэкап — часть `T-702`, а не этого ранбука.
