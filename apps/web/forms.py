"""Разбор `application/x-www-form-urlencoded` без новой зависимости (TZ §15, `T-102`).

Почему разбор свой, а не штатный `request.form()`/`Form(...)` из FastAPI: он требует
`python-multipart`, а это новая зависимость runtime-слоя. По TZ §15 (§15 «стоп-точка: новая
зависимость») её появление согласуется с заказчиком отдельно — ровно так, как согласовывался
`argon2-cffi` в `T-101` (ask `633f8d2b`: лицензия, advisory из OSV, наличие колёс под
`python:3.12-slim`). Молча тянуть её ради пары текстовых полей формы входа — значит обойти
стоп-точку, которую проект уже проходил один раз осознанно.

Что это означает на практике: страница входа и все текущие мутации работают на
`application/x-www-form-urlencoded` — это то, что отправляет обычная HTML-форма и то, что по
умолчанию отправляет HTMX. `multipart/form-data` (загрузка файлов) этим модулем не поддерживается,
и если она понадобится, зависимость придётся согласовать отдельно — это заметная граница, а не
деталь реализации.

Три вещи держатся здесь явно:

* **размер тела.** Предел на периметре держит Caddy (`max_header_size`, `request_body max_size` —
  ADR-003), но полагаться только на него нельзя: `web` принимает соединения и из внутренней сети
  составa, а ложный `Content-Length` при chunked-кодировании обманет проверку до чтения. Поэтому
  проверяется и заявленный размер, и фактический после накопления;
* **кэширование.** Тело читается один раз и остаётся в `request.state`: CSRF-зависимость читает
  поле `csrf_token` раньше обработчика маршрута, который читает `login` и `password`, и второй
  обработки тела быть не должно;
* **кодирование.** Тело декодируется как UTF-8 с `errors="replace"` и не как «что скажет
  браузер»: `%`-кодирование формы даёт UTF-8, а не cp1251, и доменные символы логина обязаны
  доходить до сравнения без искажений.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import parse_qsl

from fastapi import Request

#: Тип содержимого, который этот модуль разбирает. Всё остальное — пустой набор полей.
FORM_CONTENT_TYPE: Final = "application/x-www-form-urlencoded"

#: Предел тела формы. Значение заведомо больше реальной формы входа (логин + пароль + токен) и
#: заведомо меньше предела Caddy, чтобы отказ давало приложение с внятной причиной, а не обрыв
#: соединения на периметре.
MAX_FORM_BODY_BYTES: Final = 16 * 1024

#: Предел числа пар в теле: `parse_qsl` на «a&a&a&…» породил бы десятки тысяч ключей, из которых
#: нужен один.
MAX_FORM_FIELDS: Final = 64

#: Имена полей формы входа. Имена констант намеренно не содержат слова «пароль»: S105
#: (flake8-bandit) срабатывает на имя переменной, а не на значение, и константа «POLICY_PASSWORD =
#: "password"» выглядела бы как захардкоженный секрет. Значения — то, что отправляет браузер.
FIELD_LOGIN: Final = "login"
FIELD_PHRASE: Final = "password"


_SCOPE_KEY: Final = "tbot_form_fields"


def _declared_length(request: Request) -> int | None:
    """Заявленный `Content-Length` либо `None`, если он не разобран.

    Значение заголовку не доверяется как факту: при chunked-кодировании или просто враждебном
    клиенте оно может быть меньше реального тела, поэтому после чтения проверяется и фактический
    размер. Проверка заявленного нужна затем, чтобы не читать заведомо огромное тело.
    """
    raw = request.headers.get("content-length")
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except ValueError:
        return None


class FormBodyTooLarge(ValueError):
    """Тело формы не проходит предел — заявленный или фактический."""


async def form_fields(request: Request) -> dict[str, str]:
    """Поля формы текущего запроса; пустой словарь, если тела формы нет.

    Повторный вызов возвращает уже разобранный набор: тело читается ровно один раз.
    """
    cached = request.scope.get(_SCOPE_KEY)
    if isinstance(cached, dict):
        return cached
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    fields: dict[str, str] = {}
    if content_type == FORM_CONTENT_TYPE:
        declared = _declared_length(request)
        if declared is not None and declared > MAX_FORM_BODY_BYTES:
            raise FormBodyTooLarge(f"заявлено {declared} байт, предел {MAX_FORM_BODY_BYTES}")
        body = await request.body()
        if len(body) > MAX_FORM_BODY_BYTES:
            raise FormBodyTooLarge(f"получено {len(body)} байт, предел {MAX_FORM_BODY_BYTES}")
        pairs = parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        if len(pairs) > MAX_FORM_FIELDS:
            raise FormBodyTooLarge(f"полей {len(pairs)}, предел {MAX_FORM_FIELDS}")
        for name, value in pairs:
            # последнее значение выигрывает осознанно: «a=1&a=2» — приём подмены, и молча выбрать
            # первое означало бы, что обработчик и проверка CSRF видят разные значения
            fields[name] = value
    request.scope[_SCOPE_KEY] = fields
    return fields


def login_pair(fields: dict[str, str]) -> tuple[str, str]:
    """Значения `login` и `password` из формы.

    Ограничения по длине здесь, а не в домене: логин уходит в `citext`-колонку с уникальным
    индексом, пароль — в Argon2id (стоимость хэширования растёт с длиной входа, §8.1 держит
    минимум 12 символов, но верхнюю границу в ТЗ нет). Границы этого среза — защита от
    «формы на мегабайт», а не политика паролей: политику проверяет `packages/identity/passwords.py`
    там, где пароль устанавливают.
    """
    return fields.get(FIELD_LOGIN, "").strip()[:254], fields.get(FIELD_PHRASE, "")[:1024]
