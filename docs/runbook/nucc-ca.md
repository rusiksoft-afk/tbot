# Runbook: корень НУЦ Минцифры — доверие TLS к API брокера

Назначение: получить доверие к цепочке `*.tbank.ru` ← `Russian Trusted Sub CA` ←
`Russian Trusted Root CA`. Публичные наборы доверия (Ubuntu/Debian, `certifi`, магазины
браузеров) этот корень не содержат, поэтому «из коробки» TLS к API брокера не проходит:
замер — `docs/research/03 §3.3`, требование — `REQ-broker-gateway-02`.

Смежные документы: получение файла и попадание корня в образ — `deploy/ca/README.md`;
контроль срока и реакция на смену удостоверяющего центра — §4 и §5 этого файла (то же
проверяет `scripts/deploy_check.py`, `make deploy-check`). Содержание: §1 — какой корень
допустим и чем сверять отпечаток; §2 — серверные контуры (площадка и образ); §3 — обычный
компьютер (Windows, macOS, Linux), включая браузеры, проверки и откат; §4 — срок действия и
клиенты на `certifi`; §5 — смена удостоверяющего центра и подозрение на подмену.

## 1. Какой корень закреплён и чем сверять отпечаток

Допустим ровно один файл: `deploy/ca/ru-trusted-root-ca.pem`.

| Параметр | Значение |
|---|---|
| Отпечаток SHA-256 (DER) | `d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31` |
| Субъект | `CN=Russian Trusted Root CA, O=The Ministry of Digital Development and Communications, C=RU` |
| Срок действия | 2022-03-01 … 2032-02-27 |

Значение отпечатка закреплено в одном месте — `EXPECTED_CA_FINGERPRINT` в
`scripts/ca_policy.py`; оттуда же его берут `make deploy-check`, приёмочная проба и CI
(job `broker-tls`). Проверка локального файла (отпечаток, субъект, срок одним выводом):

```bash
openssl x509 -in deploy/ca/ru-trusted-root-ca.pem -noout -fingerprint -sha256 -subject -dates
```

Сравнение с тем, что реально отдаёт сервер: корень приходит в handshake **третьим** сертификатом
цепочки, сравнивать нужно именно его, а не листовой сертификат (bash, временные файлы удаляем):

```bash
openssl s_client -connect invest-public-api.tbank.ru:443 -showcerts </dev/null 2>/dev/null |
  awk '/BEGIN CERT/{n++} {print > ("/tmp/chain-" n ".pem")}'
for f in /tmp/chain-*.pem; do openssl x509 -in "$f" -noout -subject -fingerprint -sha256; done
rm /tmp/chain-*.pem
```

Замер 2026-11-20: `CN=*.tbank.ru` (срок до 2027-08-24) ← `Russian Trusted Sub CA` (до
2029-07-19) ← `Russian Trusted Root CA` с отпечатком `D2:6D:2D:02:…:CF:31`: файл репозитория
совпадает с серверной цепочкой. Совпадение CN ничего не доказывает: в хранилище Windows этой
машины лежат два «Russian Trusted Sub CA» с одинаковым именем и разными ключами
(`21557850…` и `BBBDE210…`) — основанием для доверия служит только отпечаток DER.

## 2. Площадка и образ (серверные контуры)

Прод-ВМ (Ubuntu 24.04):

```bash
sudo cp deploy/ca/ru-trusted-root-ca.pem /usr/local/share/ca-certificates/ru-trusted-root-ca.crt
sudo update-ca-certificates
```

Признак успеха — `curl` без `-k` отвечает HTTP-кодом (`401`), а не ошибкой цепочки. Образ:
`deploy/Dockerfile` копирует корень в `/usr/local/share/ca-certificates/ru-trusted-root-ca.crt`
и вызывает `update-ca-certificates`. Обязательные детали Debian — расширение `.crt` и верхний
уровень каталога: файл `*.pem` или файл в подкаталоге `update-ca-certificates` не замечает, а
сборка и `up --wait` при этом остаются зелёными (так и падал первый вариант Dockerfile —
подробности в `docs/acceptance/broker-tls.md`). Наличие корня в системном наборе образа
проверяет шаг job'а `compose-smoke`, пару «без корня — отказ, с корнем — успех» — job
`broker-tls`. Приёмка на площадке — `make deploy-check` (она же печатает срок действия
сертификата брокера). Полные шаги — `deploy/ca/README.md §2–3`. Раздел ниже — про машину
разработчика: там порядок отличается, потому что хранилища доверия в десктопных ОС устроены
иначе.

Ограничение серверного способа: `update-ca-certificates` чинит доверие тем клиентам, которые
читают системный набор (`curl`, `openssl`, `ssl` из стандартной библиотеки, Chromium/Edge).
Клиенты на `certifi` — `httpx`, `requests`, SDK брокера — системное хранилище не видят; для
них отдельный разбор в §4.3.

## 3. Установка корня на обычный компьютер (не сервер)

После установки корня в хранилище ОС TLS к `invest-public-api.tbank.ru` проходит у `curl`,
`openssl`, у браузеров (кроме Firefox: у него своё хранилище, §3.7) и у Python на Windows. Файл — из
репозитория или официальной страницы корней НУЦ, сверка отпечатка (§3.1) обязательна.

### 3.1 Проверка отпечатка перед установкой

Windows, `cmd` (строка корректна и в PowerShell — `certutil` есть в обеих оболочках):

```bat
certutil -dump deploy\ca\ru-trusted-root-ca.pem | findstr /i d26d2d02
```

Найдено полное значение `d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31`
(метка строки — «Хеш сертификата») — файл подходит; пусто или другое значение — **сертификат
ставить нельзя**: другой ключ либо подмена (прочие SHA-256-строки `certutil` — хэши открытого ключа).

То же по DER-телу сертификата, PowerShell (проверено на 5.1, в PowerShell 7 так же):

```powershell
$c = New-Object Security.Cryptography.X509Certificates.X509Certificate2((Resolve-Path deploy\ca\ru-trusted-root-ca.pem).Path)
$h = [Security.Cryptography.SHA256]::Create(); (($h.ComputeHash($c.RawData) | ForEach-Object { $_.ToString('x2') }) -join '')
$c.Subject; $c.NotBefore; $c.NotAfter
```

macOS и Linux (на Windows — `openssl` из Git for Windows), вторая команда — отпечаток DER-тела как в репозитории:

```bash
openssl x509 -in deploy/ca/ru-trusted-root-ca.pem -noout -fingerprint -sha256 -subject -dates
openssl x509 -in deploy/ca/ru-trusted-root-ca.pem -outform DER | openssl dgst -sha256
```

### 3.2 Windows 10/11

Графически: двойной клик по `ru-trusted-root-ca.pem` → «Установить сертификат…» → место хранения
«Локальный компьютер» (или «Текущий пользователь», если администратора нет) → «Поместить все
сертификаты в следующее хранилище» → «Обзор…» → «Доверенные корневые центры сертификации» →
«ОК» → «Далее» → «Готово», затем полный перезапуск браузеров (§3.7).

Командой, `cmd` (в PowerShell те же команды, кавычки — только для путей с пробелами):

```bat
certutil -addstore -f Root deploy\ca\ru-trusted-root-ca.pem
certutil -addstore -user Root deploy\ca\ru-trusted-root-ca.pem
```

Первая строка — хранилище локального компьютера (нужен администратор), вторая — только текущий
пользователь, без администратора; `-f` перезаписывает экземпляр с тем же отпечатком, экземпляр с
другим сначала удаляют (§3.9). Наличие в хранилище компьютера: `certutil -verifystore Root "Russian Trusted Root CA"` (в пользовательском хранилище поиск по имени иногда даёт `NTE_NOT_FOUND` — там надёжнее перечисление PowerShell ниже). Нужный ли это корень (PowerShell):

```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match 'Russian Trusted Root CA' } |
  ForEach-Object { $_.GetCertHashString('SHA256') + '  ' + $_.NotBefore.ToString('yyyy-MM-dd') + '..' + $_.NotAfter.ToString('yyyy-MM-dd') }
```

Ожидаем строку с началом `D26D2D02`; даты — в местном поясе (`2022-03-02..2032-02-28`). Python на
Windows берёт набор доверия **не из PEM-файла, а из реестра**: `ssl` читает хранилище «Доверенные
корневые центры сертификации» — и для компьютера, и для текущего пользователя, поэтому проба Python проходит
без переменных окружения. `httpx` и `requests` читают свой комплект (`certifi`) и системное
хранилище не видят: для них доверие — механизм SDK (`ssl_tbank_verify`, п.2 `docs/research/03 §3.3`).

### 3.3 macOS

`-d` — настройки доверия административной области (все пользователи и службы), `-r trustRoot` —
«доверять как корню». У `verify-cert` на части версий macOS вывод неполон, главный признак — `curl` (§3.8):

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain deploy/ca/ru-trusted-root-ca.pem
security dump-trust-settings -d
security verify-cert -c deploy/ca/ru-trusted-root-ca.pem
curl -v https://invest-public-api.tbank.ru/swagger/docs/v1
```

### 3.4 macOS: метка «Всегда доверять» в «Связке ключей»

Одной связки ключей мало: у сертификата должна быть доверительная настройка, иначе Chromium/Edge
его не примут (цепочку они проверяют через Security framework и смотрят на неё), хотя `curl`
проходит. «Связка ключей» (Keychain Access) → связка «Система» → «Сертификаты» → двойной клик по
«Russian Trusted Root CA» → раскрыть «Доверие» → «Когда используется этот сертификат: Всегда
доверять» (в подпункте «SSL» — тоже) → пароль администратора → перезапуск браузера. Командная
форма — `-r trustRoot` из §3.3, без неё симптом один: `curl` работает, браузер нет.

### 3.5 Linux на базе Debian/Ubuntu

```bash
sudo cp deploy/ca/ru-trusted-root-ca.pem /usr/local/share/ca-certificates/ru-trusted-root-ca.crt
sudo update-ca-certificates
```

Расширение именно `.crt` и форма PEM — иначе `update-ca-certificates` файл не увидит; в выводе ожидаем
«1 added certificates». Наличие — проверкой из §3.8 (`--expect-anchor` + `--bundle /etc/ssl/certs/ca-certificates.crt`).

### 3.6 Linux на базе RPM (RHEL, AlmaLinux, Fedora)

```bash
sudo cp deploy/ca/ru-trusted-root-ca.pem /etc/pki/ca-trust/source/anchors/ru-trusted-root-ca.pem
sudo update-ca-trust
```

Готового пакета с этим корнем в инфраструктуре проекта нет — путь только что описан. Наличие:
`trust list | grep -i 'Russian Trusted'` и проба из §3.8
(`--bundle /etc/pki/tls/certs/ca-bundle.crt`).


### 3.7 Браузеры: Chromium/Edge и Firefox — разные хранилища

- **Chromium/Edge/Chrome на Windows** берут системное хранилище сертификатов. Нужен **полный
  перезапуск браузера**: закрыть все окна и фоновые процессы (в Edge отключить «ускоренный
  запуск»), иначе открытый процесс переиспользует результат проверки. `-user Root` браузер видит,
  если запущен от этого пользователя; на macOS эти браузеры берут связку ключей и требуют §3.4.
- **Firefox имеет собственное хранилище** и системное не читает: `about:preferences` →
  «Приватность и защита» → «Сертификаты» → «Просмотр сертификатов…» → вкладка «Доверенные центры
  сертификации» → «Импортировать…» → выбрать `deploy/ca/ru-trusted-root-ca.pem` → отметить
  «Доверять при идентификации веб-сайтов» → ОК (на macOS путь тот же, источник — файл): установок
  §3.2–§3.4 для Firefox **недостаточно**.
- Признак, что браузер корень не увидел: `ERR_CERT_AUTHORITY_INVALID` (Chromium/Edge) или
  `SEC_ERROR_UNKNOWN_ISSUER` (Firefox), если `curl` с этой же машины проходит.

### 3.8 Как убедиться, что заработало

```bash
curl -v https://invest-public-api.tbank.ru/swagger/docs/v1
```

Нужен HTTP-ответ, а не ошибка цепочки: код роли не играет (замер 2026-11-20 с dev-машины — `HTTP/1.1 404` при успешном
TLS), важно отсутствие `SSL certificate problem` / `CERTIFICATE_VERIFY_FAILED`; на REST-пути — `401`/`405`. Проверка из Python штатным контекстом (`ssl` берёт набор доверия ОС):

```python
import socket, ssl

context = ssl.create_default_context()  # проверку не отключаем
with context.wrap_socket(socket.create_connection(("invest-public-api.tbank.ru", 443), 10),
                         server_hostname="invest-public-api.tbank.ru") as tls:
    print("TLS OK:", tls.version(), tls.cipher()[0], "сертификат до:", tls.getpeercert()["notAfter"])
```

Проба проекта различает «цепочка не доверена» и «связи нет», третья строка — наличие корня в PEM-связке ОС (§3.5–§3.6):

```bash
python scripts/tls_trust_probe.py --host invest-public-api.tbank.ru --expect reachable
python scripts/tls_trust_probe.py --host invest-public-api.tbank.ru --expect verified
python scripts/tls_trust_probe.py --expect-anchor d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31 --bundle /etc/ssl/certs/ca-certificates.crt
```

`reachable` — путь есть, `verified` — цепочка доверена штатному набору ОС (замер 2026-11-20 на
dev-машине Windows: `[verified]`, exit 0). На сервере то же проверяет `make deploy-check` (без `make` на
Windows — `.\make.ps1 deploy-check`): отпечаток корня, срок сертификата брокера, коннект без `-k`.

### 3.9 Удаление и откат

Windows, `cmd` (хранилище компьютера — от администратора, вариант `-user` — без):

```bat
certutil -delstore Root "Russian Trusted Root CA"
certutil -delstore -user Root "Russian Trusted Root CA"
```

macOS (сначала снимается доверительная настройка, затем сертификат из связки), Debian/Ubuntu, RPM:

```bash
sudo security remove-trusted-cert -d deploy/ca/ru-trusted-root-ca.pem
sudo security delete-certificate -c "Russian Trusted Root CA" /Library/Keychains/System.keychain
sudo rm /usr/local/share/ca-certificates/ru-trusted-root-ca.crt && sudo update-ca-certificates
sudo rm /etc/pki/ca-trust/source/anchors/ru-trusted-root-ca.pem && sudo update-ca-trust
```

Firefox удаляется там же, где импортировался (§3.7). После отката — полный перезапуск браузеров и терминалов;
приложение сразу вернётся к честному `unverified` (§3.8), но доверие теряют и другие сайты на этом корне (например, портал госуслуг).

### 3.10 Чего делать нельзя

- **Не отключать проверку сертификата**: `verify=False`, `ssl.CERT_NONE`, `curl -k`, `--insecure`.
  В проекте это запрещено конфигурацией (`ssl_tbank_verify=false` не проходит валидатор
  `packages/common/config.py`) и тестом `test_проверка_tls_нельзя_отключить…`.
- **Не делать постоянным решением подмену набора доверия переменными окружения**
  (`SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`): на время разбора допустимо, постоянное доверие живёт в хранилище ОС (§3.2–§3.6), иначе поведение расходится между `curl`, Python, браузером и контейнером.
- **Не брать корень со сторонних сайтов и зеркал**: только выдача официальной страницы корней НУЦ или файл репозитория с проверенным отпечатком (§3.1); имя «Russian Trusted Root CA» — не основание, основание — отпечаток DER.
- **Не править сторонние комплекты доверия** (`certifi`-связку в venv, `--extra-ca` как штатный механизм): путь один — `deploy/ca/` и `update-ca-certificates` (§2), а `--extra-ca` в пробе нужен только для проверки механизма на собственной ЦС в CI.

## 4. Срок действия: кто следит и что делать заранее

### 4.1 Что проверяется автоматически

- `make deploy-check`, проверка `ca_bundle`: файл существует, отпечаток совпадает с
  закреплённым, корень самоподписан, срок не истёк и до его конца осталось не меньше
  `MIN_ROOT_DAYS_LEFT` (90 суток). Границы и отпечаток — `scripts/ca_policy.py`.
- `make deploy-check`, проверка `broker_tls`: адрес брокера берётся по контуру, в выводе
  печатается срок сертификата брокера; если до его конца меньше `MIN_LEAF_DAYS_LEFT`
  (14 суток), проверка краснеет с текстом «сертификат брокера почти истёк».
- job `broker-tls` в CI: на каждом пуше пробираются живые точки брокера — без якоря
  ожидается `unverified`, с закреплённым корнем — `verified`. Смена удостоверяющего центра
  не может пройти незамеченной: она ломает именно этот job.
- шаг job'а `compose-smoke`: корень входит в системный набор доверия образа, и из
  контейнера `engine` строится живой handshake к обеим точкам брокера.

### 4.2 Замер сроков и календарь

| Сертификат | Срок окончания | Что это значит |
|---|---|---|
| `Russian Trusted Root CA` | 2032-02-27 | наша зона ответственности: готовим замену заранее (§5) |
| `Russian Trusted Sub CA` | 2029-07-19 | зона ЦС/брокера; наших действий нет, если цепочка остаётся на том же корне |
| `*.tbank.ru` (листовой) | 2027-08-24 | перевыдаёт брокер; наших действий не требуется |

Ближайшая дата, за которой надо следить, — 2029-07-19 (промежуточный): при его перевыпуске
важно, чтобы он по-прежнему подписывался тем же корнем. Проверка — отпечаток корня в
цепочке сервера (§1) и зелёный job `broker-tls`. Корень: за 90 суток до конца срока
`deploy-check` покраснеет сам; это не авария, а требование начать §5.

### 4.3 Клиенты на `certifi` (`httpx`, `requests`, SDK брокера)

`update-ca-certificates` им не помогает: `certifi` читает собственную связку из пакета
(`.../site-packages/certifi/cacert.pem`), а не системный набор. Признак — та же ошибка
цепочки при исправном `curl`. Это не отмена проверки: `ssl_tbank_verify=false`
не проходит валидатор `packages/common/config.py`, и отключать проверку нельзя (§3.10).

Сейчас это заметно только на dev-машине: корень в хранилище Windows есть, штатный `ssl`
проходит, а `httpx` — нет. На сервере эффект тот же. Правильное действие — дать клиенту
явную связку, в которой есть и публичные корни, и закреплённый корень НУЦ:

```python
import httpx

bundle = "/etc/tbot/ca-bundle.pem"  # системная связка + deploy/ca/ru-trusted-root-ca.pem
client = httpx.Client(verify=bundle, timeout=10)
```

Связку собирают явно и проверяют по отпечатку
(`python3 scripts/ca_policy.py --verify-bundle /etc/tbot/ca-bundle.pem`), а не подменяют её
переменными окружения. В коде приложения это делается вместе с клиентом брокера (T-012), не
раньше. Телеграм при этом не ломается: его цепочка подписана общедоступными ЦС, которые в
`certifi` есть, — поэтому `apps/tgbot` работает и без этого шага.

## 5. Смена удостоверяющего центра и подозрение на подмену

Признаки: job `broker-tls` упал при исправной сети; `ca_bundle` сообщил «отпечаток не
совпадает»; в handshake появился другой промежуточный или корневой сертификат; `broker_tls`
краснеет с `unverified`, хотя корень в системе есть.

Порядок действий:

1. Ничего не добавлять в доверие, пока причина не понятна. Проверить, какой именно сертификат
   отдает сервер (§1), и сравнить с закрепленным отпечатком — возможно, подменён не корень, а
   листовой сертификат (это другой случай: брокер перевыпускает его сам).
2. Подтвердить вне канала, по которому пришёл новый сертификат: официальная страница корней
   НУЦ, две независимые AIA-выдачи (файлы должны совпасть байт в байт), письменный ответ
   брокера о смене ЦС.
3. Если смена подтверждена: положить новый корень в `deploy/ca/` (имя прежнее), заменить
   `EXPECTED_CA_FINGERPRINT` в `scripts/ca_policy.py`, обновить таблицу §1 и границы срока,
   пересобрать образы, переустановить корень на площадке (§2) и на dev-машине (§3), дождаться
   зелёного CI (`broker-tls` и шаг compose-smoke), записать факт в `docs/acceptance/` и в
   `docs/HANDOFF.md`: дата, новый и старый отпечатки, кто проверял.
   Старый корень из доверенных не удалять, пока хоть одна рабочая цепочка на него опирается.
   Закреплённый отпечаток в `ca_policy.py` при этом остаётся ровно один — тот, которым
   подписана рабочая цепочка брокера.
4. Если подтверждение не получено или цепочка изменилась без объявления брокера — это
   подозрение на перехват: доверие не добавлять, контур не поднимать, эскалация по
   `docs/tz/15 §15.5` (S1), запись в `docs/incidents/` обязательна. Секреты, которые могли
   уйти по перехваченному каналу, отзывать по `docs/runbook/telegram-token.md` и процедуре
   отзыва токена у брокера.

Последствия для доверия: один и тот же корень доверяется отдельно в каждом контуре — образ
(`deploy/Dockerfile`), площадка (§2), dev-машина (§3), браузер (§3.7), клиенты на `certifi`
(§4.3). После смены ЦС нужно пройтись по всем пяти, иначе часть площадок останется с
устаревшим доверием и начнёт падать на TLS.
