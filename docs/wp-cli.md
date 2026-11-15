# Справочник WP-CLI

[Документация](README.md) · [Расследование](recovery.md) · [MCP](mcp.md)

Выполняйте команды из корня WordPress или передавайте `--path`. Для расследования укажите `--user` с правом `site_defense_investigate` или `manage_options`. Для применения и отмены плана необходим `manage_options`. WP-CLI запускается с системными полномочиями оператора, поэтому ограничьте доступ к оболочке по правилам хостинга.

```sh
wp --path=/srv/www/wordpress site-defense status
wp help site-defense
wp help site-defense cleanup
```

## Проверки и пакеты

| Задача | Действия после `wp site-defense` |
| --- | --- |
| Полное файловое сканирование | `scan run`, `scan resume`, `scan pause`, `scan status`, `scan results`, `scan skipped --page=1` |
| Исключения по пути и SHA-256 | `scan exclusions`, `scan exclude SELECTOR`, `scan unexclude EXCLUSION_KEY` |
| Быстрое наблюдение | `watch status`, `watch run`. Для запуска включите быстрое наблюдение в настройках. |
| Сверка известных уязвимостей | `vulnerabilities`. Проверяет доступные локальные данные и при необходимости ставит обновление WPVulnerability в очередь. |
| Аудит базы данных | `db-audit run`, `db-audit status`, `db-audit findings` |
| Подтверждение прав | `db-audit trusted`, `db-audit trust USER_ID FINGERPRINT`, `db-audit untrust USER_ID`. Отпечаток указан в `db-audit findings --format=json`. |
| База уязвимостей и сигнатуры | `database status`, `database import FILE.pack`, `malware status`, `malware import FILE.pack` |
| Правила WAF | `rules status`, `rules import FILE.pack`, `rules mode RULE_ID observe`, `rules rollback`. Доступные режимы `observe`, `block`, `off`. |

Для `scan run`, `scan resume`, `watch run` и `db-audit run` стандартное ограничение составляет 300 секунд. Укажите `--timeout=0`, чтобы снять ограничение времени самой команды. При частичном проходе проверьте `status` и при необходимости продолжите сканирование. Формат по умолчанию JSON. Для читаемого вывода поддерживаемых команд добавьте `--format=table`.

В планировщике учитывайте, что код `0` означает успешное выполнение команды. `1` означает ошибку или остановку по тайм-ауту. `2` означает наличие находок при явном `--fail-on-findings` в `scan`, `db-audit` или `vulnerabilities`. Пропуски файлов и ошибки отчёта проверяйте отдельно по `scan status` и `scan skipped`.

```sh
wp site-defense scan run --timeout=900 --fail-on-findings
wp site-defense scan skipped --page=1 --format=json
wp site-defense db-audit run --timeout=300 --fail-on-findings
wp site-defense vulnerabilities --fail-on-findings
```

## Реагирование и обслуживание

| Задача | Действия после `wp site-defense` |
| --- | --- |
| Карантин | `quarantine list`, `quarantine move SELECTOR`, `quarantine restore QUARANTINE_ID` |
| Восстановление официального файла | `repair preview SELECTOR`, `repair apply PREVIEW_ID`, `repair undo QUARANTINE_ID` |
| Инциденты | `incidents list`, `incidents respond INCIDENT_ID ACTION`. Действия `sessions`, `password`, `scan`, `quarantine`, `resolve`. |
| Режим инцидента | `response status`, `response preview`, `response start`, `response stop`. При предпросмотре и запуске можно выбрать `--minutes`, `--sessions` и `--passwords`. |
| Хронология | `timeline --hours=24 --limit=1000` |
| Расследование | `investigate --hours=24 --limit=80`, `mcp`. Для обоих можно передать `--access-log=PATH`. |
| План очистки | `cleanup prepare TARGET_ID[,TARGET_ID]`, `cleanup show PLAN_ID`, `cleanup preview PLAN_ID STEP_ID`, `cleanup verify PLAN_ID`, `cleanup apply PLAN_ID STEP_ID`, `cleanup undo PLAN_ID STEP_ID`. Для шага восстановления файла передайте `--repair-preview=PREVIEW_ID`. |
| Сигнал и доставка | `heartbeat status`, `heartbeat send`, `notifications status`, `notifications test`, `notifications deliver` |
| Отзыв собственных сессий | `revoke-sessions` от выбранного через `--user` пользователя. |
| Политика 2FA | `policy status`, `policy enable`, `policy disable` |

SELECTOR берите из `scan results`. `cleanup preview` показывает предпросмотр шага очистки содержимого базы. Команды с подтверждением принимают `--yes`, если оператор уже проверил выбранную цель. Для аварийного возвращения доступа используйте инструкцию по восстановлению. [Восстановление доступа](installation.md#восстановление-доступа)

## Запуск по расписанию

Site Defense использует WP-Cron для фоновых проверок и доставки. На малопосещаемом сайте задайте системный планировщик с запуском каждую минуту от пользователя сайта. Например, строка в пользовательском crontab на Linux выглядит так.

```cron
* * * * * /usr/local/bin/wp --path=/srv/www/wordpress cron event run --due-now
```

Подставьте реальные пути и проверьте выполнение задач. После этого можно отключить запуск WP-Cron с веб-запросов константой `DISABLE_WP_CRON` в `wp-config.php`. Крупные разовые сканирования можно выполнять отдельно с `wp site-defense scan run`.
