#!/usr/bin/env bash
# Применение правил из deploy/vps/ufw.rules на рабочей ВМ (TZ §8.3, §14.5; задача T-708).
#
# Зачем скрипт, а не «просто набор команд»: включение ufw с политикой deny incoming без
# предварительных правил обрывает текущий SSH-вход, то есть ошибка в порядке шагов стоит
# доступа к машине. Скрипт гарантирует порядок, показывает что делает и умеет откатываться.
#
#   sudo bash deploy/vps/firewall.sh            # разбор правил, показ команд без изменений
#   sudo bash deploy/vps/firewall.sh --apply    # применить и включить
#   sudo bash deploy/vps/firewall.sh --revert   # откат: ufw disable (правила не удаляются)
#
# После --apply ОБЯЗАТЕЛЬНО проверить вход НОВЫМ соединением, не закрывая текущее:
#   ssh -i ~/.ssh/tbot/ssh-key-1795095923419 rusiksoft@153.51.172.30 'echo ok'
# Если новый вход не поднимается — в текущем окне сразу: sudo ufw disable

set -euo pipefail

RULES_FILE="$(dirname "$0")/ufw.rules"
MODE="${1:-show}"
SSH_KEY_NOTE="ssh -i ~/.ssh/tbot/ssh-key-1795095923419 rusiksoft@153.51.172.30 'echo ok'"

if [[ ! -f "$RULES_FILE" ]]; then
    echo "не найден файл правил: $RULES_FILE" >&2
    exit 2
fi

if [[ "$MODE" == "--revert" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "для --revert нужен root (sudo)" >&2
        exit 2
    fi
    echo "ОТКАТ: ufw disable (правила остаются в памяти ufw, но не применяются)"
    ufw disable
    ufw status verbose
    exit 0
fi

if [[ "$MODE" != "show" && "$MODE" != "--apply" ]]; then
    echo "неизвестный режим: $MODE (ожидается --apply, --revert или пусто)" >&2
    exit 2
fi

commands=()
forward_policy=""
while IFS= read -r raw || [[ -n "$raw" ]]; do
    # \\r на конце ломал бы разбор порта молча (правило «22/tcp\r» не совпадает ни с чем),
    # поэтому CR снимается сразу: файл мог приехать с Windows-концовками.
    raw="${raw%$'\r'}"
    line="${raw%%#*}"
    line="$(echo "$line" | xargs)"
    [[ -z "$line" ]] && continue

    kind="${line%% *}"
    rest="${line#* }"
    case "$kind" in
        policy)
            # policy <направление> <политика> -> ufw default <политика> <направление>
            direction="${rest%% *}"
            policy="${rest#* }"
            if [[ "$direction" == "routed" ]]; then
                # ufw читает политику пересылки из /etc/default/ufw, и там имена политик
                # пакета фильтра (ACCEPT/DROP), а не слова ufw. У Ubuntu по умолчанию DROP —
                # с ним у контейнеров не работает исходящий трафик.
                case "$policy" in
                    allow) forward_policy="ACCEPT" ;;
                    deny) forward_policy="DROP" ;;
                    *)
                        echo "для routed ожидается allow или deny, получено: $policy" >&2
                        exit 2
                        ;;
                esac
            else
                commands+=("ufw default $policy $direction")
            fi
            ;;
        allow)
            # allow <порт>/<протокол> comment <назначение>
            spec="${rest%% comment*}"
            commands+=("ufw allow $spec")
            ;;
        *)
            echo "неизвестная строка правила: $raw" >&2
            exit 2
            ;;
    esac
done < "$RULES_FILE"

echo "файл правил: $RULES_FILE"
for command in "${commands[@]}"; do
    echo "  $command"
done
if [[ -n "$forward_policy" ]]; then
    echo "  /etc/default/ufw: DEFAULT_FORWARD_POLICY=\"$forward_policy\""
fi
echo "  ufw --force enable"

if [[ "$MODE" == "show" ]]; then
    echo
    echo "это разбор без изменений: для применения добавить --apply"
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "для --apply нужен root (sudo)" >&2
    exit 2
fi

for command in "${commands[@]}"; do
    # Правила разобраны из собственного файла, разбиение на слова намеренное.
    # shellcheck disable=SC2086
    $command
done

if [[ -n "$forward_policy" ]]; then
    sed -i "s|^DEFAULT_FORWARD_POLICY=.*|DEFAULT_FORWARD_POLICY=\"$forward_policy\"|" /etc/default/ufw
    echo "/etc/default/ufw: $(grep '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw)"
fi

ufw --force enable
ufw status verbose
echo
echo "Правила применены. Проверить вход НОВЫМ соединением, текущее окно не закрывать:"
echo "  $SSH_KEY_NOTE"
echo "Откат, если новый вход не поднимается: sudo ufw disable"
