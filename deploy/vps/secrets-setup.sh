#!/usr/bin/env bash
# Ввод секретов площадки (TZ §14.3, задача T-712; процедура — docs/runbook/secrets-on-host.md).
#
# Кто запускает: только заказчик, в своей SSH-сессии, от root (`sudo bash …`) или через `sudo -s`.
# Значения запрашиваются в скрытом режиме (`read -s`), поэтому они не попадают ни в историю
# оболочки (встроенная команда read ничего не пишет в history), ни в argv (`ps aux` пуст), ни в
# вывод. Агент значения не видит и не запрашивает: ему нужны только имена файлов и права.
#
#   sudo bash /opt/tbot/deploy/vps/secrets-setup.sh            # ввод значений
#   sudo bash /opt/tbot/deploy/vps/secrets-setup.sh --check    # проверка наличия и прав
#
# --check ничего не меняет и не печатает содержимое: только имя, размер в байтах и режим.
#
# Почему файлы, а не переменные окружения: TZ §8.4 запрещает учётные данные в env-аргументах
# (`docker run -e`) и в аргументах командной строки — и то и другое видно через `ps aux` и попадает
# в логи сборщика/CI. compose читает их как `secrets:` и монтирует в /run/secrets read-only.

set -euo pipefail

# Имена файлов = имена в compose (`deploy/compose.prod.yaml`), а не имена полей конфигурации:
# compose сам монтирует файл под именем секрета. `telegram_socks_user`/`telegram_socks_pass`
# здесь не обрабатываются: они созданы и приняты раньше, в составе туннеля Telegram (T-714).
# TBOT_SECRETS_SETUP_DIR — только для проверки скрипта в CI (job `prod-config` прогоняет его на
# временном каталоге с фиктивными значениями); на площадке каталог по умолчанию. Имя не совпадает
# с TBOT_SECRETS_DIR (это переменная приложения, каталог секретов для `Settings`): столкнуться с
# ней в одном job было бы ловушкой, а не экономией.
SECRETS_DIR="${TBOT_SECRETS_SETUP_DIR:-/etc/tbot/secrets}"
SECRET_NAMES=(db_password db_url ghcr_token telegram_token)

# Ключ БД для `docker login ghcr.io` — единственное назначение: pull образов по digest
# (docs/runbook/ghcr-pull.md §3). В контейнер он не монтируется: реестр трогает хост.
usage() {
  echo "использование: $0 [--check]" >&2
  echo "  --check — проверить наличие файлов и права (без изменений и без содержимого)" >&2
}

check_mode() {
  if [[ ! -d "$SECRETS_DIR" ]]; then
    echo "FAIL: каталога нет: $SECRETS_DIR" >&2
    return 1
  fi
  local dir_mode failed=0
  dir_mode=$(stat -c '%a' "$SECRETS_DIR")
  if [[ "$dir_mode" != "700" ]]; then
    echo "WARN: режим каталога $SECRETS_DIR = $dir_mode, ожидался 700" >&2
  fi
  local name path
  for name in "${SECRET_NAMES[@]}"; do
    path="$SECRETS_DIR/$name"
    if [[ ! -f "$path" ]]; then
      echo "FAIL: нет файла: $path" >&2
      failed=1
      continue
    fi
    local mode owner size
    mode=$(stat -c '%a' "$path")
    owner=$(stat -c '%U:%G' "$path")
    size=$(stat -c '%s' "$path")
    if [[ "$mode" != "600" || "$owner" != "root:root" ]]; then
      echo "FAIL: $path: режим $mode, владелец $owner (ожидались 600 и root:root)" >&2
      failed=1
      continue
    fi
    if (( size == 0 )); then
      echo "FAIL: $path: пустой файл" >&2
      failed=1
      continue
    fi
    # Содержимое не печатается: достаточно размера, чтобы увидеть обрезание или опечатку.
    echo "OK   $path: ${size} байт, $mode, $owner"
  done
  return $failed
}

if [[ "${1:-}" == "--check" ]]; then
  check_mode
  exit $?
fi

if [[ $# -gt 0 ]]; then
  usage
  exit 2
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "запускать от root: sudo bash $0 (или через sudo -s)" >&2
  exit 1
fi

# История отключается на время всего запуска: подстраховка для случая `sudo -s`, где пользователь
# может что-то напечатать открыто. Значения в историю и так не попадают (read -s), но режим
# «пустой истории на время скрипта» дешевле, чем объяснять, что именно не попадает.
HISTORY_ENABLED=0
if [[ -o history ]]; then
  HISTORY_ENABLED=1
  set +o history
fi
trap 'if [[ "$HISTORY_ENABLED" == "1" ]]; then set -o history; fi' EXIT

umask 077
install -d -m 700 -o root -g root "$SECRETS_DIR"

# Ловушка bash, на который этот цикл уже спотыкался: `name val written=0` — это не объявление
# трёх переменных, а запуск команды `name` с аргументами (`command not found` при первом же
# прогоне). Объявление переменной без значения в bash пишется отдельно или через `declare`.
# Поймал не человек, а поведенческий прогон скрипта в job `prod-config` (прогон 44716225556):
# на dev-машине цикл не исполняется, потому что скрипт требует root.
written=0
for name in "${SECRET_NAMES[@]}"; do
  if [[ -e "$SECRETS_DIR/$name" ]]; then
    existing_mode=$(stat -c '%a' "$SECRETS_DIR/$name")
    existing_size=$(stat -c '%s' "$SECRETS_DIR/$name")
    printf 'Файл %s уже существует (%s байт, режим %s). Перезаписать? [y/N] ' \
      "$SECRETS_DIR/$name" "$existing_size" "$existing_mode"
    read -r -n 1 answer
    echo
    if [[ "$answer" != "y" && "$answer" != "Y" ]]; then
      echo "пропущено: $name"
      continue
    fi
  fi
  # `IFS= read -r -s`: без -r обратный слэш в пароле съедался бы, без IFS= ведущие и замыкающие
  # пробелы обрезались бы (в пароле они законны). -s — без эха.
  val=""
  IFS= read -r -s -p "Введите значение для $name: " val
  echo
  if [[ -z "$val" ]]; then
    echo "пустое значение: $name не записан (проверьте, что ввод не пропустили)" >&2
    continue
  fi
  # `printf '%s'` без перевода строки: приложение читает файл как есть, и лишний \n в конце
  # для DSN и токена — это «пароль не подходит», который ищут сутки.
  printf '%s' "$val" >"$SECRETS_DIR/$name"
  chown root:root "$SECRETS_DIR/$name"
  chmod 600 "$SECRETS_DIR/$name"
  unset val
  written=$((written + 1))
done

echo
echo "записано файлов: $written"
check_mode
