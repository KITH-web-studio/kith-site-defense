# Сборка, подпись и выпуск Site Defense

[Документация](README.md) · [История версий](../CHANGELOG.md) · [GitHub Releases](https://github.com/KITH-web-studio/kith-site-defense/releases)

## Подготовка стендов

Для релизного прогона нужны PowerShell 7, Python с `requests` и `polib`, два локальных WordPress, WP-CLI и PHP с Sodium и ZipArchive. Используйте отдельные тестовые базы на адресах loopback, например `127.0.0.1`.

1. На первом стенде установите минимальные версии WordPress и PHP из [заголовка плагина](../site-defense/site-defense.php). На втором включите WooCommerce, HPOS и Checkout Block. Откройте витрину тестового магазина, чтобы режим Coming Soon не перехватывал запрос проверки оформления заказа.
2. В `wp-config.php` обоих стендов установите `WP_ENVIRONMENT_TYPE` в `local` и `SD_RELEASE_LAB` в `true`. Для воспроизводимых замеров можно задать `DISABLE_WP_CRON`. Создайте администратора `sdrelease-admin` с ID `1` и сохраните пароль каждого стенда в отдельном локальном файле.
3. Настройте журналы и передачу ID в PHP. Для стенда с FastCGI установите `user_ini.cache_ttl=0`, чтобы проверка сразу видела включение и выключение раннего WAF. [Конфигурация прокси](mcp.md#журнал-обратного-прокси)
4. Подготовьте ZIP предыдущего релиза и два тестовых подписанных пакета, базы уязвимостей и WAF, с версиями выше встроенных. Для них используется действующий ключ подписи пакетов данных.

## Релизный прогон

Обновите номер версии в плагине и историю изменений. Запускайте сборку из корня репозитория, подставляя пути и URL каждого стенда.

```text
python tools/release.py --plain WP_PATH URL PHP PROXY_LOG PASSWORD_FILE --shop WP_PATH URL PHP PROXY_LOG PASSWORD_FILE --wp-cli WP_CLI_PHAR --previous PREVIOUS_ZIP --database TEST_DATABASE_PACK --rules TEST_WAF_PACK --output site-defense.zip --report output/release.json
```

Скрипт проверяет состав ZIP, встроенные данные, PHP и переводы. Затем на том же ZIP проверяет установку, обновление и возврат предыдущей версии, доступ к MCP и админке, вход и ранний WAF, импорт пакетов, очистку и её отмену, Checkout Block и тестовый платёжный колбэк с HPOS. Email и Telegram проверяются через перехват транспорта. Замер сравнивает выключенный плагин, включённый плагин и включённый плагин во время полного CLI-сканирования. [Методика проверки сканера](../SCANNER-TEST-REPORT.md)

По итогам успешного прогона ZIP записывается по `--output`, а JSON-отчёт с версиями, замерами и SHA-256 — по `--report`. Перед публикацией проверьте выбранные сценарии на копии целевого сайта с его темой, плагинами и настройками хостинга.

## GitHub Releases

1. Подпишите прошедший проверки ZIP **ключом релизов**. Открытый ключ этой пары находится в [конфигурации обновлений](../site-defense/data/plugin-updates.json). Храните закрытый ключ за пределами Git.
2. Создайте тег `vVERSION` на соответствующем коммите. `VERSION` должен совпадать с заголовком `Version` внутри ZIP.
3. Прикрепите к черновику на GitHub три файла из сборки. Это `site-defense.zip` и два файла из каталога подписи, `site-defense-update.json` и `site-defense-update.sig`. Сверьте SHA-256 ZIP с отчётом.
4. Для тега `vX.Y.Z-rc.N` отметьте выпуск как предварительный. Стабильный релиз публикуется для канала по умолчанию. После публикации проверьте обнаружение и установку из WordPress на стенде с предыдущей версией.

```text
php tools/sign-plugin-release.php site-defense.zip RELEASE_SIGNING_KEY RELEASE_OUTPUT_DIRECTORY
```

Связка репозитория, версии, требований, размера и хеша ZIP проверяется по подписанному манифесту. Сайты получают файлы из публичного GitHub Releases через HTTPS.

## База уязвимостей

Используйте действующий **ключ пакетов данных**. Его открытая часть находится в [конфигурации источника](../site-defense/data/update.json). Для уже установленных копий сохраняйте ту же пару ключей. Команда `php tools/create-signing-key.php PRIVATE_KEY_PATH` предназначена для создания новой пары.

Передайте `WORDFENCE_INTELLIGENCE_TOKEN` сборщику через окружение и запустите сборку полного снимка Wordfence Intelligence Production Feed v3.

```text
python tools/build-feed.py --signing-key PRIVATE_KEY_PATH --output FEED_DIRECTORY --seed-dir site-defense/data
pwsh -File tools/package.ps1
```

Чтобы публиковать отдельные обновления данных, передайте `--url https://your-domain.example/path` и запускайте обновление без `--seed-dir`. На уже установленном сайте можно задать этот адрес через `SITE_DEFENSE_FEED_URL` в `wp-config.php`, если открытый ключ совпадает. Публикуйте сначала `database-<version>.pack`, затем `latest.json`. Пакет также можно [импортировать вручную](protection.md#источники-уязвимостей). Сайт проверяет подпись с открытым ключом, токен Wordfence остаётся у сборщика. Сохраняйте уведомления и ссылки на источники в распространяемых данных. [Лицензия Wordfence Intelligence](https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/) · [Лицензия WPVulnerability](https://www.wpvulnerability.com/license/)

## Подписанные пакеты правил

Для WAF возьмите за основу [встроенный JSON](../site-defense/data/waf-rules.json), укажите схему `2` и увеличьте `version`. Правило задаёт компонент и диапазон версий, маршрут `front`, `plugin`, `rest` или `any`, HTTP-методы и обязательные условия. Операторы `present`, `equals` и `traversal` проверяют выбранные параметры GET и POST, заголовки или `pagename`. Максимум 100 правил на пакет. После импорта начните с наблюдения и проверьте журнал и сценарии сайта перед переходом к блокировке.

Источники встроенных правил указаны в официальных бюллетенях. [WordPress CVE-2026-87902](https://wordpress.org/documentation/wordpress-version/version-7-1-2/) · [WooPayments CVE-2023-28121](https://developer.woocommerce.com/2023/03/23/critical-vulnerability-detected-in-woocommerce-payments-what-you-need-to-know/) · [Canto CVE-2026-3335](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/canto/canto-311-missing-authorization-to-unauthenticated-file-upload)

Для сигнатур сканера используется [схема встроенного набора](../site-defense/data/malware-rules.json). Укажите схему `1` и увеличьте `version`. Каждое правило содержит уникальный `id`, `title` и `confidence` (`high`, `medium` или `low`). Поддерживаются `php_request_execution`, `php_decoded_execution`, `php_loader_write`, `js_decoded_execution`, `literal` и `sha256`. Поле `value` у `literal` содержит 8–256 байт, у `sha256` — 64 шестнадцатеричных символа в нижнем регистре.

Подпишите оба типа пакетов тем же ключом, что и базу уязвимостей. Импортируйте отдельно через админку или WP-CLI. [Команды импорта](wp-cli.md#проверки-и-пакеты)

```text
php tools/sign-rules.php RULES_JSON PRIVATE_KEY_PATH OUTPUT_PACK
```
