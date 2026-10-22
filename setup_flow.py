"""Pure, serializable setup state machine shared by current/future native clients."""
def flow(state):
    def step(stage, number, title, detail, button, action, blocked=False, tone="normal"):
        return dict(stage=stage, step=number, total=4, title=title, detail=detail,
                    primary_title=button, action=action, blocked=blocked, tone=tone)

    platform = state.get("platform", {})
    if platform and not platform.get("supported"):
        return step("unsupported", 0, "Система пока не поддерживается", platform.get("reason", "Нужен Intel Mac с macOS 13+."), "Недоступно", "none", True, "warning")
    if state.get("status_error") or not state:
        return step("unavailable", 0, "Не удалось проверить состояние", "Повторите проверку. Если ошибка сохраняется, откройте журнал в разделе обслуживания.", "Повторить проверку", "refresh", tone="warning")
    session = state.get("session")
    if session is not None:
        return step("external_session", 4, "Уже работает другой сеанс", "Завершите разделение в его окне. Второй сеанс не будет запущен.", "Сеанс уже запущен", "none", True)
    if state.get("latest_status") in ("rollback_unconfirmed", "recovery_failed"):
        if not state.get("service", {}).get("installed"):
            return step("recovery_unavailable", 0, "Нужна помощь с восстановлением", "Откат не подтверждён, а установленный помощник недоступен. Не удаляйте журнал и не начинайте новый сеанс. Сохраните отчёт и используйте прежнее средство восстановления или помощь администратора.", "Восстановление недоступно", "none", True, "warning")
        return step("recovery", 0, "Нужно восстановление", "Предыдущий откат не подтверждён. Сначала проверим и удалим только собственные временные маршруты.", "Восстановить маршруты", "recover", tone="warning")
    if not state.get("profile", {}).get("ready"):
        return step("profile", 1, "Выберите рабочий профиль", "Получите приватный JSON-файл через внутренний канал. Выберите его один раз — настройки останутся только на этом Mac. Пароли и MFA в файл не входят.", "Выбрать файл профиля…", "import-profile")
    service = state.get("service", {})
    if not state.get("preflight", {}).get("forticlient_available", True):
        return step("missing_forti", 2, "Нужен FortiClient", "Установите официальный FortiClient по правилам вашей организации, затем повторите проверку. Приложение не загружает VPN-клиент самостоятельно.", "Повторить проверку", "refresh", tone="warning")
    if not service.get("installed") or not service.get("current"):
        return step("access", 2, "Разрешите изменение маршрутов", "Для работы нужна отдельная системная служба. Следующая кнопка откроет запрос macOS: пароль вводится только в системном окне. Повторно при обычном включении он не нужен.", "Обновить системный доступ…" if service.get("installed") else "Разрешить системный доступ…", "install")
    if not state.get("helper_healthy"):
        return step("health", 2, "Проверим системный доступ", "Проверка связи и аварийного завершения помощника не меняет сеть и не требует нового пароля.", "Проверить доступ", "health")
    if state.get("vpn_error"):
        return step("vpn_error", 4, "Проверьте подключённые VPN", "Не удалось однозначно определить поддерживаемый FortiClient SSL VPN. Отключите другие VPN; IPsec и неоднозначные профили пока не поддерживаются. Подробности — в журнале.", "Повторить проверку", "refresh", tone="warning")
    if not state.get("prepared"):
        if state.get("vpn"):
            return step("disconnect", 3, "Сначала отключите VPN", "Для подготовки нужен обычный интернет без FortiClient. Отключите VPN в его окне; мастер продолжит после обновления состояния.", "Открыть FortiClient", "open-forti")
        return step("network", 3, "Проверим обычный интернет", "VPN должен быть отключён. Проверим текущую сеть и два HTTPS-сайта. После подготовки откроется FortiClient; его пароль и MFA вводите только там.", "Подготовить подключение", "prepare")
    if not state.get("vpn"):
        return step("connect", 4, "Подключите рабочий VPN", "Откройте FortiClient и завершите вход с MFA. Не закрывайте это окно — готовность будет определена автоматически. VPN в виртуальной машине должен быть отключён.", "Открыть FortiClient", "open-forti")
    return step("ready", 4, "Можно включить разделение", "Интернет пойдёт напрямую, рабочие IPv4 — через VPN. После включения проверьте рабочий стол и звонок. Ограничения 30 минут нет; окно нужно оставить открытым.", "Включить разделение", "enable")
