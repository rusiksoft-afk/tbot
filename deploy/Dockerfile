# syntax=docker/dockerfile:1.7
#
# Единый многоступенчатый образ для всех четырёх процессов: какой процесс запускать, задаётся
# build-аргументом APP (web | engine | tgbot | jobs). Так зависимости считаются один раз, а
# различия между процессами остаются в конфиге и команде запуска.
#
# Требования, закреплённые здесь:
#   * процесс работает от непривилегированного пользователя (uid 10001);
#   * python:3.12-slim, версия фиксируется в CI по digest (TZ §14.6);
#   * корневой сертификат НУЦ Минцифры устанавливается из deploy/ca (T-709): без него проверка
#     TLS брокера не проходит, и это должно быть видно как ошибка сборки/проверки, а не как
#     отключение проверки;
#   * образ пригоден для read_only rootfs: запись возможна только в /tmp (tmpfs в compose).

FROM python:3.12-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
# build-essential нужен только для сборки колёс; в runtime-слой он не попадёт.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends build-essential \
    && rm -rf -- /var/lib/apt/lists/*
COPY pyproject.toml ./
COPY apps ./apps
COPY packages ./packages
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install .

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/rusiksoft-afk/tbot" \
      org.opencontainers.image.title="tbot" \
      org.opencontainers.image.licenses="Proprietary"

RUN groupadd --gid 10001 tbot \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin tbot

# Корневой сертификат НУЦ: имя и расположение задаёт scripts/ca_policy.py (CA_IMAGE_FILE).
# Debian `update-ca-certificates` читает только файлы `*.crt` в верхнем уровне
# `/usr/local/share/ca-certificates`: вариант «`ru-trusted-root-ca.pem` в подкаталоге `tbot/`»
# собирался зелёным, а в связку корень не попадал (проверено в CI job `compose-smoke`).
# Подкаталог не случаен: в верхнем уровне имя файла уникально, но расширение — обязательное `.crt`.
COPY deploy/ca/ru-trusted-root-ca.pem /usr/local/share/ca-certificates/ru-trusted-root-ca.crt
RUN update-ca-certificates

COPY --from=builder /opt/venv /opt/venv
WORKDIR /srv/tbot
COPY migrations ./migrations
COPY alembic.ini ./
COPY configs ./configs
COPY apps ./apps
COPY packages ./packages

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=UTC

ARG APP=web
ENV TBOT_APP=${APP}

USER 10001:10001

# shell-форма нужна только для подстановки TBOT_APP; сам процесс запускается через exec,
# чтобы сигналы (SIGTERM) приходили напрямую ему, а не оболочке.
CMD ["sh", "-c", "exec python -m apps.${TBOT_APP}.main"]
