#!/usr/bin/env bash
# Ввод секретов рабочего контура на ВМ 153.51.172.30.
#
# Кто запускает: только заказчик (или тот, кому заказчик передал значения), из интерактивного
# SSH-сеанса. Агент значения не вводит и не видит
# (docs/adr/ADR-003-prod-deploy-edge-decisions.md §6).
#
#   sudo bash deploy/vps/secrets-setup.sh                 # ввод
#   sudo bash deploy/vps/secrets-setup.sh --check         # только диагностика
#   sudo bash deploy/vps/secrets-setup.sh --only ghcr_token telegram_token   # перезалить одно
#
# Что гарантирует скрипт:
#   - значения читаются скрыто (`IFS= read -r -s`) и не попадают в argv, stdout, stderr или
#     историю оболочки (`set +o history`);
#   - файл получает режим 600 и владельца root:root, каталог — 700 (TZ §8.3, §14.3);
#   - в файле нет завершающего перевода строки (`printf '%s'`): DSN и токен читаются «как есть»,
#     лишний `\n` в DSN ломает подключение к базе уже на `migrate`;
#   - значение проверяется по форме ДО записи. Наличие файла и режим 600 о значении не говорят
#     ничего: замер 2026-11-20 на площадке дал зелёный `--check` при значениях не по назначению —
#     в `db_url` попали 11 цифр, в `ghcr_token` — 11 символов не-PAT, в `db_password` — фраза с
#     пробелами, а `telegram_token` не создан вовсе (docs/acceptance/tls-edge.md §2.2, строка 6);
#   - `db_password` не нужно придумывать и переносить через буфер обмена: по пустому вводу он
#     генерируется (`openssl rand -hex`), а `db_url` скрипт составляет из него сам — рассинхон
#     «скопировали не ту строку» становится невозможен (docs/runbook/secrets-on-host.md §4.1).
#
# Формы значений и признаки подмены: docs/runbook/secrets-on-host.md §4.1.
set -euo pipefail
umask 077

if [ "$(id -u)" -ne 0 ]; then
    printf 'Нужен root: sudo bash %s\n' "$0" >&2
    exit 1
fi

# Намеренно отдельная переменная от TBOT_SECRETS_DIR: последнюю читает приложение
# (packages.common.config.SECRET_FIELDS) и docker-compose, не этот скрипт.
SECRETS_DIR="${TBOT_SECRETS_SETUP_DIR:-/etc/tbot/secrets}"

# Параметры БД внутри состава (deploy/compose.yaml: POSTGRES_USER / POSTGRES_DB / порт сервиса).
# Нужны, чтобы собрать db_url из db_password. Для внешней базы правятся окружением.
DB_USER="${TBOT_DB_USER:-tbot}"
DB_HOST="${TBOT_DB_HOST:-postgres}"
DB_PORT="${TBOT_DB_PORT:-5432}"
DB_NAME="${TBOT_DB_NAME:-tbot}"
DB_PASSWORD_BYTES="${TBOT_DB_PASSWORD_BYTES:-24}" # длина генерируемого пароля в байтах
DB_PASSWORD_MIN=16
DB_PASSWORD_MAX=64

# Имена файлов задаёт compose (`file: /etc/tbot/secrets/<имя>`), а не имена секретов внутри
# контейнера (`tg_bot_token`, `tg_socks_password`): путаница даёт красный вывод на готовой
# площадке (docs/runbook/stand-deploy.md §8).
SECRET_NAMES=(db_password db_url ghcr_token telegram_token)
# Файлы, которые состав обязано потребовать, но создаёт не этот скрипт.
HOST_ONLY_NAMES=(telegram_socks_pass)

CHECK_ONLY=0
FORCE=0
ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        --force) FORCE=1 ;;
        --only)
            shift
            while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do
                ONLY="$ONLY,$1,"
                shift
            done
            if [ -z "$ONLY" ]; then
                printf 'после --only нужен список имён: --only ghcr_token telegram_token\n' >&2
                exit 2
            fi
            continue
            ;;
        --only=*) ONLY=",${1#--only=}," ;;
        --help | -h)
            sed -n '1,32p' "$0"
            exit 0
            ;;
        *)
            printf 'неизвестный аргумент: %s\n' "$1" >&2
            exit 2
            ;;
    esac
    shift
done

install -d -m 700 -o root -g root "$SECRETS_DIR"

# ───────────────────────────── форма значений ─────────────────────────────
# Проверка по всему значению (якоря ^…$). В вывод уходят только имя, длина и подсказка формата:
# значение не печатается ни целиком, ни по частям.
hint() {
    case "$1" in
        db_password)
            printf 'пароль базы: %d–%d символов без пробелов и спецсимволов (он же внутри db_url); пустой ввод = сгенерировать' \
                "$DB_PASSWORD_MIN" "$DB_PASSWORD_MAX"
            ;;
        db_url)
            printf 'postgresql+psycopg://<user>:<пароль>@<хост>:<порт>/<база>; скрипт составляет сам из db_password'
            ;;
        ghcr_token)
            printf 'token GitHub для ghcr.io с правами Packages: Read-only и Contents: Read-only (github_pat_…, gh…_… или классический hex-40)'
            ;;
        telegram_token)
            printf 'token бота из @BotFather: <цифры>:<35 символов>; до двоеточия только цифры'
            ;;
        telegram_socks_pass)
            printf 'пароль SOCKS-входа туннеля Telegram: 8–128 символов без пробелов'
            ;;
        *) printf 'значение' ;;
    esac
}

shape_ok() {
    case "$1" in
        db_password)
            printf '%s' "$2" | grep -Eq "^[A-Za-z0-9._~-]{${DB_PASSWORD_MIN},${DB_PASSWORD_MAX}}$"
            ;;
        db_url)
            printf '%s' "$2" | grep -Eq \
                '^postgres(ql|ql\+psycopg)://[A-Za-z][A-Za-z0-9_]*:[^@[:space:]]+@[A-Za-z0-9._-]+:[0-9]{2,5}/[A-Za-z][A-Za-z0-9_]*$'
            ;;
        ghcr_token)
            printf '%s' "$2" | grep -Eq '^(github_pat_[A-Za-z0-9_]{22,}|gh[pousr]_[A-Za-z0-9]{36,}|[0-9a-f]{40})$'
            ;;
        telegram_token) printf '%s' "$2" | grep -Eq '^[0-9]{6,12}:[A-Za-z0-9_-]{35}$' ;;
        telegram_socks_pass) printf '%s' "$2" | grep -Eq '^[^[:space:]]{8,128}$' ;;
        *) return 0 ;;
    esac
}

# ───────────────────────────── диагностика: --check ─────────────────────────────
check_mode() {
    # --check ничего не записывает: читает метаданные и форму значения, печатает имя, размер,
    # режим, владельца и вердикт формы. Значение в переменную кладёт в локальную и не выводит.
    local name path size mode owner probe failed=0
    for name in "${SECRET_NAMES[@]}" "${HOST_ONLY_NAMES[@]}"; do
        path="$SECRETS_DIR/$name"
        if [ ! -f "$path" ]; then
            printf 'FAIL: нет файла: %s\n' "$path" >&2
            failed=1
            continue
        fi
        size=$(stat -c '%s' "$path")
        mode=$(stat -c '%a' "$path")
        owner=$(stat -c '%U:%G' "$path")
        if [ "$size" -eq 0 ]; then
            printf 'FAIL: %s: пустой файл\n' "$name" >&2
            failed=1
            continue
        fi
        probe=$(<"$path")
        if ! shape_ok "$name" "$probe"; then
            printf 'FAIL: %s: значение не по форме (%s байт) — ожидалось: %s\n' \
                "$name" "$size" "$(hint "$name")" >&2
            failed=1
            probe=""
            continue
        fi
        probe=""
        if [ "$mode" != "600" ] || [ "$owner" != "root:root" ]; then
            printf 'FAIL: %s: %s байт, %s, %s (нужно 600 root:root)\n' "$name" "$size" "$mode" "$owner" >&2
            failed=1
            continue
        fi
        printf 'OK:   %s: %s байт, %s, %s\n' "$name" "$size" "$mode" "$owner"
    done
    local dir_mode
    dir_mode=$(stat -c '%a' "$SECRETS_DIR")
    if [ "$dir_mode" != "700" ]; then
        printf 'WARN: режим каталога %s = %s, ожидался 700 (иначе любой локальный юзер видит имена секретов)\n' \
            "$SECRETS_DIR" "$dir_mode" >&2
    fi
    if [ "$failed" -eq 0 ]; then
        printf 'готово: все файлы состава на месте и по форме\n'
    fi
    return "$failed"
}

if [ "$CHECK_ONLY" -eq 1 ]; then
    check_mode
    exit $?
fi

# Значения не должны попадать в историю оболочки этого сеанса.
set +o history 2>/dev/null || true

# Если пароль базы уже лежит на диске и его не вводят заново, DSN собирается из существующего
# значения: оператору не нужно знать пароль, чтобы пересобрать пару файлов.
existing_password=""
if [ -f "$SECRETS_DIR/db_password" ]; then
    existing_password=$(<"$SECRETS_DIR/db_password")
fi
db_password_value="$existing_password"

# ───────────────────────────── ввод ─────────────────────────────
# Результат — в val; значение нигде не выводится (печатается только длина и вердикт формы).
write_file() {
    local name="$1" path reply
    path="$SECRETS_DIR/$name"
    if [ ! -t 1 ] && [ "$FORCE" -eq 0 ]; then
        printf 'INTERACTIVE_REQUIRED: %s — нужен терминал (или --force)\n' "$name" >&2
        return 1
    fi
    if [ -e "$path" ] && [ "$FORCE" -eq 0 ] && [ -t 0 ]; then
        printf '  %s: файл уже есть (%s байт). Перезаписать? [y/N]: ' "$name" "$(stat -c '%s' "$path")"
        reply=""
        IFS= read -r reply
        case "$reply" in
            y | Y | yes | YES) ;;
            *)
                printf '  %s: пропущено\n' "$name"
                return 0
                ;;
        esac
    fi
    printf '%s' "$val" >"$path"
    chmod 600 "$path"
    chown root:root "$path"
    printf '  %s: записано (%s байт)\n' "$name" "$(stat -c '%s' "$path")"
    return 0
}

ask_value() {
    local name="$1" attempt reply
    for attempt in 1 2 3; do
        val=""
        printf '  %s [%s]: ' "$name" "$(hint "$name")"
        IFS= read -r -s val
        printf '\n'
        if [ -z "$val" ]; then
            if [ "$name" = "db_password" ]; then
                if [ -n "$existing_password" ] && shape_ok db_password "$existing_password"; then
                    val="$existing_password"
                    printf '  db_password: оставлен существующий (%s байт)\n' "${#val}"
                    return 0
                fi
                if [ -n "$existing_password" ]; then
                    printf '  db_password: лежащее значение не по форме — генерируется новое\n' >&2
                fi
                val=$(openssl rand -hex "$DB_PASSWORD_BYTES")
                printf '  db_password: сгенерирован автоматически (%s символов)\n' "${#val}"
                return 0
            fi
            if [ -f "$SECRETS_DIR/$name" ]; then
                printf '  %s: пустой ввод — существующий файл не меняется\n' "$name"
                if ! shape_ok "$name" "$(<"$SECRETS_DIR/$name")"; then
                    printf '  ВНИМАНИЕ: лежащее значение %s не по форме — состав с ним не стартует\n' \
                        "$name" >&2
                fi
            else
                printf '  %s: значение не введено\n' "$name" >&2
            fi
            val=""
            return 1
        fi
        if shape_ok "$name" "$val"; then
            return 0
        fi
        printf '  НЕ ПОДХОДИТ: %s (%s символов) не по форме: %s\n' \
            "$name" "${#val}" "$(hint "$name")" >&2
        if [ "$attempt" -eq 3 ]; then
            printf '  %s: записать это значение несмотря на форму? [y/N]: ' "$name"
            IFS= read -r reply
            case "$reply" in
                y | Y | yes | YES) return 0 ;;
                *)
                    val=""
                    return 1
                    ;;
            esac
        fi
        printf '  повторите ввод\n' >&2
    done
    val=""
    return 1
}

written=0
skipped=""
for name in "${SECRET_NAMES[@]}"; do
    if [ -n "$ONLY" ] && [[ "$ONLY" != *",$name,"* ]]; then
        continue
    fi
    if [ "$name" = "db_url" ]; then
        # Не спрашивается: DSN собирается из db_password (или из TBOT_DB_URL для внешней базы).
        # Именно рассинхон «скопировали не ту строку» дал 2026-11-20 пару файлов, где db_url не
        # является DSN вообще.
        if [ -n "${TBOT_DB_URL:-}" ]; then
            val="$TBOT_DB_URL"
        else
            val="postgresql+psycopg://${DB_USER}:${db_password_value}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
        fi
        if ! shape_ok "$name" "$val"; then
            printf 'FAIL: db_url: собранный DSN не по форме — проверьте TBOT_DB_* и db_password\n' >&2
            skipped="$skipped $name"
            continue
        fi
    elif ! ask_value "$name"; then
        skipped="$skipped $name"
        continue
    fi
    if [ "$name" = "db_password" ]; then
        db_password_value="$val"
    fi
    if write_file "$name"; then
        written=$((written + 1))
    else
        skipped="$skipped $name"
    fi
    val=""
    unset val
done

if [ "$written" -gt 0 ]; then
    printf '\nзаписано файлов: %s\n' "$written"
fi
if [ -n "$skipped" ]; then
    printf 'не записано:%s\n' "$skipped" >&2
    printf 'повторить: sudo bash %s --only%s\n' "$0" "${skipped}" >&2
fi
for name in "${HOST_ONLY_NAMES[@]}"; do
    if [ ! -f "$SECRETS_DIR/$name" ]; then
        printf 'WARN: нет %s — его создаёт настройка туннеля Telegram (T-714), не этот скрипт\n' \
            "$SECRETS_DIR/$name" >&2
    fi
done

printf '\nпроверка готовности:\n'
printf '  sudo bash %s --check\n' "$0"
printf 'состав (deploy/compose.prod.yaml) ждёт эти файлы:\n'
for name in "${SECRET_NAMES[@]}" "${HOST_ONLY_NAMES[@]}"; do
    printf '  %s\n' "$name"
done
exit 0
