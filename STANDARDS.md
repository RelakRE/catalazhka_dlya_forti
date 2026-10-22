# Применимые стандарты и практики

Проверка выполнена 22 октября 2026 для Intel-ветки 1.3.0. Это рабочий набор
требований, не заявление о сертификации, полном соответствии всем документам
или независимом аудите. HIG/CWE — руководства и классификация, не сертификаты.

| Источник | Применение в проекте | Как проверяем |
| --- | --- | --- |
| [NIST SSDF SP 800-218, финальная версия 1.1](https://csrc.nist.gov/pubs/sp/800/218/final), PW.7/PW.8 | Анализ кода и проверки исполняемого поведения; регрессии на найденные ошибки | `REVIEW.md`, автоматические сценарии IPC/отката/импорта, честный список ручной приёмки |
| Тот же SSDF, PW.4 и PS.2 | Контроль стороннего runtime и целостности поставки | Закреплённый SHA-256 Python, лицензии, проверка payload, `codesign`, ZIP-roundtrip и SHA256SUMS; хеш не заменяет подтверждение издателя |
| [Apple HIG: Dark Mode](https://developer.apple.com/design/human-interface-guidelines/dark-mode) | Следовать системной теме, пользоваться адаптивными цветами, проверять оба оформления | Нет принудительной Aqua; системные фоны/цвета, отдельные dark/light предпросмотры без изменения системных настроек |
| [Apple HIG: Onboarding](https://developer.apple.com/design/human-interface-guidelines/onboarding) | Краткие объяснения рядом с действием, настройка через реальные шаги | Мастер профиль → доступ → сеть → VPN; одно основное действие, без дублирующего запроса пароля |
| [Apple HIG: Accessibility](https://developer.apple.com/design/human-interface-guidelines/accessibility) и [Layout](https://developer.apple.com/design/human-interface-guidelines/layout) | Читаемые подписи, адаптивная раскладка, клавиатура/доступность, статус не только цветом | Auto Layout, прокрутка, основные описания 15 pt, accessibility-подписи, текст статуса; полная ручная проверка VoiceOver/high contrast ещё нужна |
| [RFC 8259 / STD 90](https://www.rfc-editor.org/rfc/rfc8259) | Однозначный JSON и рекомендуемая уникальность имён полей | Более строгий профиль проекта отвергает дубли/NaN/Infinity, ограничивает размер, допускает UTF-8 BOM для совместимости с редакторами |
| [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Чеклист валидации на границах; не присвоение CVE | Разрешённые поля/типы/IPv4, проверка в root до запуска работника, отсутствие команд/путей в профиле |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) | Уменьшать гонки между проверкой файла и чтением | Установщик читает ограниченные файлы через открытые directory FD / openat / O_NOFOLLOW, проверяет уже открытый дескриптор |
| [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | Ограничения ресурсов и времени, корректное завершение | Абсолютный дедлайн handshake, лимит клиентов/сообщений, ограниченный GUI-журнал, watchdog только read-only status; работающий откат не убивается |

## Ограничения доказательств

Нельзя заменить реальную приёмку VPN одними mocks/скриншотами. В частности,
автотесты не подтверждают корпоративное разрешение, доступность рабочих серверов,
живую MFA, аудио/видео, отсутствие всех утечек либо совместимость с любым EMS.
Нет независимого pentest, исчерпывающего fuzzing и проверки каждой комбинации ОС.

Доверие к скачанной неподписанной сборке — отдельный остающийся риск. Требуемый
для нормального распространения путь — [Developer ID и notarization Apple](https://developer.apple.com/developer-id/),
а не команды отключения Gatekeeper/SIP. Внутренние данные не включаются в релиз.

## Будущий Windows-порт

## Дополнение 1.4 — 23 октября 2026

- [Apple SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice/mainapp):
  opt-in login item с реальным системным статусом и видимой ошибкой, без скрытого
  launchd-автозапуска маршрутов.
- [NSRunningApplication.hide](https://developer.apple.com/documentation/appkit/nsrunningapplication/hide()):
  скрывать Forti штатным API вместо Accessibility/имитации ввода; не завершать VPN.
- SSDF PW.7/PW.8: review автомата, stale status, привязки own PID и once-only
  side effects; UI-тесты отмены, ошибок, чужого сеанса и чтения настроек.
- CWE-367/770: bounded descriptor read настроек с O_NOFOLLOW/fstat, 64 KiB,
  ограничение ожидания входа. Уменьшение поставки проверяет идентичность удаляемых
  дублей и не меняет байты рабочего интерпретатора/stdlib.

### Основа Windows

Изучены первичные Microsoft-документы: [CreateIpForwardEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2),
[безопасность named pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[проверка impersonation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient).
Они влияют на проектирование будущего адаптера, но не означают, что он уже реализован.
Нельзя переносить в Windows проверку macOS UID, Unix-права или имена enN/utunN
как будто они эквивалентны Windows SID/DACL/InterfaceLuid.
