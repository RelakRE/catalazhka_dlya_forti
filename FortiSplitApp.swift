import AppKit
import UniformTypeIdentifiers
import CryptoKit
import ServiceManagement

final class FlippedDocument: NSView {
    override var isFlipped: Bool { true }
}

final class SystemBackground: NSView {
    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        dirtyRect.fill()
    }
    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

final class SystemCard: NSView {
    override func draw(_ dirtyRect: NSRect) {
        NSColor.controlBackgroundColor.setFill()
        let path = NSBezierPath(roundedRect: bounds.insetBy(dx: 0.5, dy: 0.5), xRadius: 12, yRadius: 12)
        path.fill()
        NSColor.separatorColor.setStroke()
        path.lineWidth = 1
        path.stroke()
    }
    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSTabViewDelegate {
    var window: NSWindow!
    let statusLabel = NSTextField(wrappingLabelWithString: "Проверка состояния…")
    let detailLabel = NSTextField(wrappingLabelWithString: "")
    let stageLabel = NSTextField(labelWithString: "")
    let errorLabel = NSTextField(wrappingLabelWithString: "")
    let primary = NSButton(title: "Подождите…", target: nil, action: nil)
    let tabs = NSTabView()
    let workTabButton = NSButton(title: "Работа", target: nil, action: nil)
    let settingsTabButton = NSButton(title: "Настройки", target: nil, action: nil)
    let setupOptions = NSStackView()
    let rdpCheck = NSButton(checkboxWithTitle: "Открывать рабочий стол после подключения", target: nil, action: nil)
    let trueConfCheck = NSButton(checkboxWithTitle: "Запускать TrueConf после подключения", target: nil, action: nil)
    let hideFortiCheck = NSButton(checkboxWithTitle: "Скрывать окно FortiClient после подключения", target: nil, action: nil)
    let loginCheck = NSButton(checkboxWithTitle: "Открывать Forti Split при входе в macOS", target: nil, action: nil)
    let wizardRDP = NSButton(checkboxWithTitle: "Автоматически открывать рабочий стол", target: nil, action: nil)
    let wizardTrueConf = NSButton(checkboxWithTitle: "Автоматически запускать TrueConf", target: nil, action: nil)
    let wizardHideForti = NSButton(checkboxWithTitle: "Скрывать FortiClient после успешного подключения", target: nil, action: nil)
    let chooseRDP = NSButton(title: "Выбрать RDP-файл…", target: nil, action: nil)
    let rdpLabel = NSTextField(wrappingLabelWithString: "RDP-файл не выбран")
    let settingsError = NSTextField(wrappingLabelWithString: "")
    let removeButton = NSButton(title: "Удалить системный помощник…", target: nil, action: nil)
    let importButton = NSButton(title: "Заменить профиль…", target: nil, action: nil)
    let recoverButton = NSButton(title: "Восстановить маршруты", target: nil, action: nil)
    let healthButton = NSButton(title: "Проверить доступ", target: nil, action: nil)
    let reportsButton = NSButton(title: "Отчёты", target: nil, action: nil)
    let logsButton = NSButton(title: "Журнал", target: nil, action: nil)
    let progress = NSProgressIndicator()
    let steps = NSStackView()
    var stepLabels: [NSTextField] = []
    var state: [String: Any] = [:]
    var refreshing = false
    var worker: Process?
    var workerInput: Pipe?
    var workerAction = ""
    var stopping = false
    var pendingQuit = false
    var configuring = false
    var logText = ""
    var lastError = ""
    var dataRoot: URL!
    var timer: Timer?
    var fortiURL: URL?
    var preferences = WorkplacePreferences()
    var workplace = WorkplaceRun()
    var preferencesError = false
    var stateEpoch = 0
    var statusItem: NSStatusItem?
    var statusAction: NSMenuItem?
    var launchNotice = ""
    var settingsContent: NSView?
    var vpnDisconnectPending = false
    var connectionEnded = false
    var installedAwaitingCheck = false
    var optionsStage: Bool {
        let stage = (state["flow"] as? [String: Any])?["stage"] as? String ?? ""
        return !preferences.setupComplete && ["network", "disconnect", "connect", "ready"].contains(stage)
    }
    var settingsURL: URL { dataRoot.appendingPathComponent("workplace-settings.json") }
    var ownsActiveSession: Bool {
        guard let process = worker, workerAction == "enable", !stopping,
              let session = state["session"] as? [String: Any],
              session["state"] as? String == "active",
              let pid = session["pid"] as? NSNumber else { return false }
        return pid.int32Value == process.processIdentifier
    }
    let resources = Bundle.main.resourceURL!
    var preview: Bool { CommandLine.arguments.contains("--preview") || CommandLine.arguments.contains("--ui-test") }
    var canStartOperation: Bool { worker == nil && !configuring && state["session"] as? [String: Any] == nil }

    func text(_ value: String, size: CGFloat = 14, weight: NSFont.Weight = .regular,
              color: NSColor = .labelColor) -> NSTextField {
        let label = NSTextField(wrappingLabelWithString: value)
        label.font = .systemFont(ofSize: size, weight: weight)
        label.textColor = color
        label.maximumNumberOfLines = 0
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        label.setContentCompressionResistancePriority(.required, for: .vertical)
        return label
    }

    func stack(_ views: [NSView], vertical: Bool = true, spacing: CGFloat = 14) -> NSStackView {
        let result = NSStackView(views: views)
        result.orientation = vertical ? .vertical : .horizontal
        result.alignment = vertical ? .leading : .centerY
        result.spacing = spacing
        result.detachesHiddenViews = true
        if vertical {
            for view in views { view.widthAnchor.constraint(equalTo: result.widthAnchor).isActive = true }
        }
        return result
    }

    func card(_ content: NSView) -> NSView {
        let box = SystemCard()
        content.translatesAutoresizingMaskIntoConstraints = false
        box.addSubview(content)
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: 22),
            content.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -22),
            content.topAnchor.constraint(equalTo: box.topAnchor, constant: 22),
            content.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -22)
        ])
        return box
    }

    func style(_ button: NSButton, action: Selector, help: String = "") {
        button.target = self
        button.action = action
        button.bezelStyle = .rounded
        button.font = .systemFont(ofSize: 14)
        button.setAccessibilityHelp(help)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Production inherits macOS appearance, including automatic live changes.
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        dataRoot = base.appendingPathComponent("Forti Split", isDirectory: true)
        if let index = CommandLine.arguments.firstIndex(of: "--data-root"), CommandLine.arguments.count > index + 1 {
            dataRoot = URL(fileURLWithPath: CommandLine.arguments[index + 1], isDirectory: true)
        }
        if !preview {
            if let existing = NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "local.fortisplit.desktop")
                .first(where: { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }) {
                existing.activate(options: [.activateIgnoringOtherApps])
                NSApp.terminate(nil)
                return
            }
            do {
                try FileManager.default.createDirectory(at: dataRoot, withIntermediateDirectories: true,
                                                       attributes: [.posixPermissions: 0o700])
                let attributes = try FileManager.default.attributesOfItem(atPath: dataRoot.path)
                guard attributes[.type] as? FileAttributeType == .typeDirectory,
                      (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else {
                    throw NSError(domain: "FortiSplit", code: 1, userInfo: [NSLocalizedDescriptionKey: "Каталог данных должен принадлежать текущему пользователю и не быть ссылкой."])
                }
                try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dataRoot.path)
                let config = dataRoot.appendingPathComponent("split-config.json")
                if !FileManager.default.fileExists(atPath: config.path) {
                    try FileManager.default.copyItem(at: resources.appendingPathComponent("split-config.json"), to: config)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: config.path)
                }
            } catch {
                alert("Не удалось открыть данные", error.localizedDescription)
                NSApp.terminate(nil)
                return
            }
            if FileManager.default.fileExists(atPath: settingsURL.path) {
                do { preferences = try WorkplacePreferences.load(settingsURL) }
                catch { preferencesError = true; lastError = "Не удалось прочитать настройки рабочего места. Проверьте их на вкладке «Настройки» и сохраните заново." }
            }
        }
        fortiURL = findForti()
        buildMenu()
        buildWindow()
        syncPreferences()
        if !preview { buildStatusItem() }
        if let index = CommandLine.arguments.firstIndex(of: "--appearance"), CommandLine.arguments.count > index + 1, preview {
            window.appearance = NSAppearance(named: CommandLine.arguments[index + 1] == "dark" ? .darkAqua : .aqua)
        }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if preview {
            setPreview(stage: CommandLine.arguments.contains("--preview-profile") ? "profile" : "ready")
            if CommandLine.arguments.contains("--preview-setup") { preferences.setupComplete = false; syncPreferences(); updateUI() }
            if CommandLine.arguments.contains("--preview-settings") { showSettings() }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
                if CommandLine.arguments.contains("--ui-test") { self.runUITests() } else { self.savePreview() }
            }
        } else {
            refresh()
            timer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { [weak self] _ in self?.refresh() }
        }
    }

    func buildMenu() {
        let menu = NSMenu()
        let root = NSMenuItem()
        menu.addItem(root)
        let application = NSMenu()
        root.submenu = application
        let settings = NSMenuItem(title: "Настройки…", action: #selector(showSettings), keyEquivalent: ",")
        settings.target = self
        application.addItem(settings)
        application.addItem(.separator())
        application.addItem(withTitle: "Завершить Forti Split", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        NSApp.mainMenu = menu
    }

    func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 720, height: 690),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Forti Split"
        window.minSize = NSSize(width: 680, height: 580)
        window.backgroundColor = .windowBackgroundColor
        window.contentView = SystemBackground(frame: NSRect(x: 0, y: 0, width: 720, height: 690))
        window.delegate = self
        window.center()
        let title = text("Forti Split", size: 28, weight: .bold)
        let subtitle = text("Рабочий VPN и обычный интернет", size: 15, color: .secondaryLabelColor)
        steps.orientation = .horizontal
        steps.spacing = 12
        steps.distribution = .fillEqually
        for name in ["Профиль", "Доступ", "Запуск", "Подключение"] {
            let label = text(name, size: 13, color: .secondaryLabelColor)
            steps.addArrangedSubview(label)
            stepLabels.append(label)
        }
        stageLabel.font = .systemFont(ofSize: 13, weight: .medium)
        stageLabel.textColor = .secondaryLabelColor
        statusLabel.font = .systemFont(ofSize: 23, weight: .semibold)
        statusLabel.maximumNumberOfLines = 0
        detailLabel.font = .systemFont(ofSize: 15)
        detailLabel.textColor = .labelColor
        detailLabel.maximumNumberOfLines = 0
        for label in [statusLabel, detailLabel, errorLabel] {
            label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            label.setContentCompressionResistancePriority(.required, for: .vertical)
        }
        errorLabel.font = .systemFont(ofSize: 13)
        errorLabel.textColor = .systemRed
        errorLabel.isHidden = true
        primary.controlSize = .large
        primary.keyEquivalent = "\r"
        style(primary, action: #selector(primaryAction))
        primary.font = .systemFont(ofSize: 15, weight: .semibold)
        primary.heightAnchor.constraint(greaterThanOrEqualToConstant: 42).isActive = true
        primary.setAccessibilityHelp("Единственное основное действие текущего этапа. Пароль и MFA вводятся только в системном окне или FortiClient.")
        progress.style = .spinning
        progress.controlSize = .small
        progress.isDisplayedWhenStopped = false
        let heading = stack([stageLabel, progress], vertical: false)
        stageLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        setupOptions.orientation = .vertical
        setupOptions.alignment = .leading
        setupOptions.spacing = 12
        for check in [wizardRDP, wizardTrueConf, wizardHideForti] {
            check.target = self; check.action = #selector(preferenceChanged)
            setupOptions.addArrangedSubview(check)
        }
        let content = stack([heading, statusLabel, detailLabel, errorLabel, setupOptions, primary], spacing: 16)
        let mainCard = card(content)
        let foot = text("IPv4 по адресам · DNS и IPv6 без изменений\nОкно можно закрыть: управление останется в строке меню. Выход из приложения завершает разделение.", size: 13, color: .secondaryLabelColor)
        style(importButton, action: #selector(importProfile), help: "Замена приватного профиля. Требует остановленного сеанса и новой подготовки.")
        style(recoverButton, action: #selector(recoverAction))
        style(healthButton, action: #selector(healthAction))
        style(reportsButton, action: #selector(openReports))
        style(logsButton, action: #selector(showLog))
        style(removeButton, action: #selector(removeHelper))
        style(chooseRDP, action: #selector(selectRDP))
        for check in [rdpCheck, trueConfCheck, hideFortiCheck] {
            check.target = self; check.action = #selector(preferenceChanged)
        }
        loginCheck.target = self; loginCheck.action = #selector(loginChanged)
        rdpLabel.font = .systemFont(ofSize: 13)
        rdpLabel.maximumNumberOfLines = 2
        settingsError.textColor = .systemRed
        let save = NSButton(title: "Сохранить настройки", target: nil, action: nil)
        style(save, action: #selector(saveSettings))
        let settingContent = stack([
            text("Рабочее место", size: 23, weight: .semibold),
            text("Автозапуск выполняется один раз после подтверждённого разделения. Пароли и MFA остаются в FortiClient и Windows App.", size: 15),
            rdpCheck, rdpLabel, chooseRDP,
            text("Выберите доверенный .rdp-файл. Адреса рабочего стола и RD Gateway должны быть в рабочем профиле. Предупреждения Windows App не отключаются.", size: 13, color: .secondaryLabelColor),
            trueConfCheck, hideFortiCheck, loginCheck,
            text("При входе в macOS открывается только интерфейс — VPN и маршруты автоматически не включаются. FortiClient скрывается, а не отключается.", size: 13, color: .secondaryLabelColor),
            settingsError, save,
            text("Профиль и обслуживание", size: 19, weight: .semibold),
            importButton, healthButton, recoverButton, reportsButton, logsButton, removeButton
        ], spacing: 14)
        settingsContent = settingContent
        let root = stack([title, subtitle, steps, mainCard, foot], spacing: 14)
        let work = NSTabViewItem(identifier: "work"); work.label = "Работа"
        work.view = scrollContent(root)
        let settings = NSTabViewItem(identifier: "settings"); settings.label = "Настройки"
        settings.view = scrollContent(settingContent)
        tabs.addTabViewItem(work); tabs.addTabViewItem(settings)
        tabs.tabViewType = .noTabsNoBorder
        tabs.delegate = self
        style(workTabButton, action: #selector(selectWorkTab))
        style(settingsTabButton, action: #selector(selectSettingsTab))
        let navigation = stack([workTabButton, settingsTabButton], vertical: false, spacing: 12)
        navigation.distribution = .fillEqually
        navigation.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(navigation)
        tabs.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(tabs)
        NSLayoutConstraint.activate([
            tabs.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 12),
            tabs.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -12),
            navigation.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 28),
            navigation.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -28),
            navigation.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 12),
            tabs.topAnchor.constraint(equalTo: navigation.bottomAnchor, constant: 12),
            tabs.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor, constant: -12)
        ])
    }

    func scrollContent(_ root: NSView) -> NSView {
        let container = NSView(frame: NSRect(x: 0, y: 0, width: 690, height: 600))
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        let document = FlippedDocument()
        document.translatesAutoresizingMaskIntoConstraints = false
        root.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(root)
        scroll.documentView = document
        container.addSubview(scroll)
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: container.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            root.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 28),
            root.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -28),
            root.topAnchor.constraint(equalTo: document.topAnchor, constant: 26),
            root.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -26)
        ])
        return container
    }

    func backend(_ action: String) -> Process {
        let process = Process()
        process.executableURL = resources.appendingPathComponent("runtime/bin/python3.12")
        let code = "import sys,runpy; sys.path.insert(0, sys.argv.pop(1)); runpy.run_module('desktop_entry', run_name='__main__')"
        process.arguments = ["-I", "-B", "-c", code, resources.path, "--data-root", dataRoot.path, action]
        if let forti = fortiURL { process.arguments! += ["--forti-path", forti.path] }
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        return process
    }

    func statusWatchdog(_ process: Process, after seconds: TimeInterval = 35) -> DispatchWorkItem {
        let watchdog = DispatchWorkItem {
            if process.isRunning {
                process.terminate()  // Only a read-only status child, never a route worker.
                DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
                    if process.isRunning { kill(process.processIdentifier, SIGKILL) }
                }
            }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: watchdog)
        return watchdog
    }

    func refresh() {
        if refreshing || preview { return }
        refreshing = true
        let epoch = stateEpoch
        DispatchQueue.global(qos: .utility).async {
            let process = self.backend("status")
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            process.standardInput = FileHandle.nullDevice
            var watchdog: DispatchWorkItem?
            var value: [String: Any]
            do {
                try process.run()
                watchdog = self.statusWatchdog(process)
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                guard let parsed = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    throw NSError(domain: "FortiSplit", code: 2, userInfo: [NSLocalizedDescriptionKey: "Неверный ответ проверки состояния."])
                }
                value = parsed
            } catch { value = ["status_error": "Проверка не завершилась. Попробуйте ещё раз; подробности доступны в журнале."] }
            watchdog?.cancel()
            let snapshot = value
            DispatchQueue.main.async {
                self.refreshing = false
                guard epoch == self.stateEpoch else { self.refresh(); return }
                self.state = snapshot
                if let message = snapshot["status_error"] as? String {
                    self.logText = String((self.logText + "\n" + message).suffix(16000))
                    self.lastError = "Не удалось проверить состояние. Повторите проверку; подробности — в журнале."
                }
                self.updateUI()
                self.advanceWorkplace()
            }
        }
    }

    func updateUI() {
        let session = state["session"] as? [String: Any]
        let active = ownsActiveSession || (preview && session?["state"] as? String == "active")
        let idle = worker == nil && !configuring && session == nil
        let flow = state["flow"] as? [String: Any] ?? [:]
        var stage = flow["step"] as? Int ?? 0
        statusLabel.textColor = .labelColor
        primary.isEnabled = idle && flow["blocked"] as? Bool != true
        importButton.isEnabled = idle
        recoverButton.isEnabled = idle
        healthButton.isEnabled = idle && (state["service"] as? [String: Any])?["current"] as? Bool == true
        for control in [rdpCheck, trueConfCheck, hideFortiCheck, loginCheck, chooseRDP,
                        wizardRDP, wizardTrueConf, wizardHideForti, removeButton] {
            control.isEnabled = idle && !workplace.requested
        }
        importButton.isEnabled = idle && !workplace.requested
        recoverButton.isEnabled = idle && !workplace.requested
        setupOptions.isHidden = !optionsStage
        steps.isHidden = preferences.setupComplete
        errorLabel.stringValue = lastError
        errorLabel.isHidden = lastError.isEmpty
        settingsError.stringValue = lastError
        settingsError.isHidden = lastError.isEmpty
        if configuring {
            stage = 2
            stageLabel.stringValue = "Этап 2 из 4 · Системный доступ"
            statusLabel.stringValue = "Разрешение запрашивает macOS"
            detailLabel.stringValue = "Подтвердите установку в системном окне. Приложение не получает и не сохраняет пароль. Дождитесь завершения."
            primary.title = "Дождитесь настройки…"
            primary.isEnabled = false
            progress.startAnimation(nil)
        } else if worker != nil {
            stageLabel.stringValue = workerAction == "health" ? "Этап 2 из 4 · Проверка доступа" : workerAction == "prepare" ? "Этап 3 из 4 · Проверка сети" : "Подключение"
            if stopping {
                statusLabel.stringValue = "Отключение и откат…"
                detailLabel.stringValue = "Удаляются только собственные временные маршруты. Не закрывайте приложение до подтверждения."
                primary.title = "Отключаем…"
                primary.isEnabled = false
            } else if workerAction == "enable" {
                statusLabel.stringValue = active ? "Разделение включено" : "Включаем и проверяем маршруты…"
                statusLabel.textColor = active ? .systemGreen : .labelColor
                detailLabel.stringValue = active ? "Интернет — напрямую, рабочие адреса — через VPN. \(launchNotice.isEmpty ? "Окно можно закрыть — приложение останется в строке меню." : launchNotice)" : "Если проверка не пройдёт, изменения будут отменены. Рабочие приложения пока не запускаются."
                primary.title = active ? "Завершить работу" : "Отменить и откатить"
                primary.isEnabled = true
            } else {
                statusLabel.stringValue = workerAction == "health" ? "Проверяем системный помощник…" : workerAction == "import-profile" ? "Импортируем профиль…" : workerAction == "recover" ? "Проверяем восстановление…" : "Проверяем обычный интернет…"
                detailLabel.stringValue = "Дождитесь результата. Следующий этап появится автоматически."
                primary.title = "Подождите…"
                primary.isEnabled = false
            }
            if active && !stopping { progress.stopAnimation(nil) } else { progress.startAnimation(nil) }
        } else if flow.isEmpty {
            stageLabel.stringValue = "Проверка приложения"
            statusLabel.stringValue = state.isEmpty ? "Получаем состояние…" : "Не удалось проверить состояние"
            detailLabel.stringValue = "Проверьте комплектность приложения. Можно повторить проверку; рабочие маршруты не меняются."
            primary.title = "Повторить проверку"
            primary.isEnabled = !refreshing
            progress.stopAnimation(nil)
        } else {
            stageLabel.stringValue = stage > 0 ? "Этап \(stage) из 4" : "Требуется внимание"
            statusLabel.stringValue = flow["title"] as? String ?? "Проверка состояния"
            detailLabel.stringValue = flow["detail"] as? String ?? ""
            primary.title = flow["primary_title"] as? String ?? "Продолжить"
            if flow["tone"] as? String == "warning" { statusLabel.textColor = .systemOrange }
            progress.stopAnimation(nil)
        }
        if idle && vpnDisconnectPending && state["vpn"] as? [String: Any] != nil {
            statusLabel.stringValue = "Разделение завершено"
            detailLabel.stringValue = "Рабочие приложения не закрывались. Отключите VPN в FortiClient: при полном VPN обычный интернет может быть недоступен до его отключения."
            primary.title = "Открыть FortiClient для отключения"
            primary.isEnabled = true
        } else if idle && optionsStage {
            stage = 3
            stageLabel.stringValue = "Первая настройка · Рабочее место"
            statusLabel.stringValue = "Что открывать после подключения?"
            detailLabel.stringValue = "Опции можно отключить или изменить на вкладке «Настройки». Выберите доверенный RDP-файл, если нужен автоматический запуск рабочего стола. При желании включите запуск при входе в macOS на вкладке настроек."
            primary.title = preferences.launchRDP && preferences.rdpPath.isEmpty ? "Выбрать RDP-файл…" : "Сохранить и продолжить"
            primary.isEnabled = true
        } else if idle && preferences.setupComplete {
            if workplace.requested {
                statusLabel.stringValue = "Ожидаем подключение FortiClient"
                detailLabel.stringValue = "Завершите вход и введите код с iPhone в FortiClient. После успешного VPN приложение само проверит разделение и откроет выбранные программы."
                primary.title = "Отменить запуск"
                primary.isEnabled = true
                progress.startAnimation(nil)
            } else if ["network", "connect", "ready", "health"].contains(flow["stage"] as? String ?? "") {
                stageLabel.stringValue = "Рабочее место"
                statusLabel.stringValue = "Готово к началу работы"
                detailLabel.stringValue = "Проверим сеть, откроем FortiClient и дождёмся вашего входа с MFA. Затем включим разделение и запустим выбранные приложения."
                primary.title = "Начать работу"
                primary.isEnabled = !preferencesError
                if connectionEnded {
                    statusLabel.stringValue = "Соединение завершено"
                    detailLabel.stringValue = "VPN отключён или сеть изменилась. Маршруты восстановлены. Нажмите «Начать работу», чтобы открыть FortiClient и подключиться заново."
                }
            }
        }
        if idle && installedAwaitingCheck && flow["stage"] as? String == "access" {
            statusLabel.stringValue = "Ожидаем системный помощник"
            detailLabel.stringValue = "Установка завершена. Повторите проверку связи — новый запрос пароля не нужен."
            primary.title = "Повторить проверку доступа"
            primary.isEnabled = true
        }
        for (index, label) in stepLabels.enumerated() {
            let names = ["Профиль", "Доступ", "Запуск", "Подключение"]
            label.stringValue = "\(index + 1 < stage ? "✓" : String(index + 1))  \(names[index])"
            label.font = .systemFont(ofSize: 13, weight: index + 1 == stage ? .semibold : .regular)
            label.textColor = index + 1 == stage ? .labelColor : .secondaryLabelColor
        }
        statusLabel.setAccessibilityLabel(statusLabel.stringValue)
        primary.setAccessibilityLabel(primary.title)
        statusAction?.title = primary.title
        statusAction?.isEnabled = primary.isEnabled
        statusItem?.button?.contentTintColor = !lastError.isEmpty ? .systemRed : active ? .systemGreen : (worker != nil || workplace.requested) ? .systemOrange : .secondaryLabelColor
        statusItem?.button?.toolTip = statusLabel.stringValue
        statusItem?.button?.setAccessibilityLabel("Forti Split: " + statusLabel.stringValue)
    }

    @objc func primaryAction() {
        if workerAction == "enable" && worker != nil { stopAction(); return }
        if workplace.requested { workplace.cancel(); updateUI(); return }
        guard canStartOperation else { return }
        lastError = ""
        connectionEnded = false
        if installedAwaitingCheck && (state["flow"] as? [String: Any])?["stage"] as? String == "access" {
            runTask("health"); return
        }
        if vpnDisconnectPending && state["vpn"] as? [String: Any] != nil { openForti(); return }
        vpnDisconnectPending = false
        if optionsStage {
            if preferences.launchRDP && preferences.rdpPath.isEmpty { selectRDP(); return }
            preferences.setupComplete = true
            if !persistPreferences() { preferences.setupComplete = false; return }
            updateUI()
            return
        }
        let stage = (state["flow"] as? [String: Any])?["stage"] as? String ?? ""
        if preferences.setupComplete && ["health", "network", "connect", "ready"].contains(stage) {
            guard !preferencesError else { showSettings(); return }
            workplace.begin()
            launchNotice = ""
            stateEpoch += 1
            updateUI()
            refresh() // Never act on a stale pre-click status snapshot.
            return
        }
        let action = (state["flow"] as? [String: Any])?["action"] as? String ?? "refresh"
        switch action {
        case "import-profile": importProfile()
        case "install": install(remove: false)
        case "open-forti": openForti()
        case "refresh": refresh()
        case "prepare", "enable", "recover", "health": runTask(action)
        default: break
        }
    }

    func runTask(_ action: String, profile: URL? = nil) {
        guard canStartOperation else { return }
        stateEpoch += 1
        let process = backend(action)
        if let file = profile { process.arguments! += ["--profile", file.path] }
        let output = Pipe()
        let input = Pipe()
        process.standardOutput = output
        process.standardError = output
        process.standardInput = action == "enable" ? input : nil
        worker = process
        workerInput = action == "enable" ? input : nil
        workerAction = action
        stopping = false
        logText = ""
        lastError = ""
        do { try process.run(); updateUI() }
        catch {
            worker = nil; workerInput = nil; workerAction = ""
            workplace.cancel()
            logText = error.localizedDescription
            lastError = WorkplaceResult.error(action: action, exit: 2)
            updateUI(); return
        }
        DispatchQueue.global(qos: .utility).async {
            // One reader owns the pipe and drains it BEFORE completion. A
            // terminationHandler racing readabilityHandler lost the last result.
            var tail = Data()
            while true {
                let chunk = output.fileHandleForReading.availableData
                if chunk.isEmpty { break }
                tail.append(chunk)
                if tail.count > 16000 { tail = tail.suffix(16000) }
            }
            process.waitUntilExit()
            let resultText = String(decoding: tail, as: UTF8.self)
            DispatchQueue.main.async {
                self.logText = resultText
                self.workerInput?.fileHandleForWriting.closeFile()
                self.workerInput = nil
                self.worker = nil
                self.workerAction = ""
                let wasStopping = self.stopping
                self.stopping = false
                self.stateEpoch += 1
                let code = process.terminationStatus
                let outcome = action == "enable" ? WorkplaceResult.outcome(output: resultText, pid: process.processIdentifier, exit: code) : ""
                if action == "enable" || code != 0 { self.workplace.cancel() }
                self.launchNotice = ""
                if outcome == "connection_ended" {
                    self.connectionEnded = true
                    self.vpnDisconnectPending = false
                    self.lastError = ""
                } else if action == "enable" && wasStopping && outcome == "stopped" {
                    self.vpnDisconnectPending = true
                    if !self.pendingQuit { self.openForti() }
                }
                if outcome == "recovery_required" || (code != 0 && code != 130 && outcome != "connection_ended") {
                    self.lastError = WorkplaceResult.error(action: action, exit: outcome == "recovery_required" ? 3 : code)
                }
                if action == "health" && code == 0 { self.installedAwaitingCheck = false }
                self.refresh()
                self.updateUI()
                if self.pendingQuit {
                    if action == "enable" && outcome == "recovery_required" {
                        self.pendingQuit = false
                        NSApp.reply(toApplicationShouldTerminate: false)
                        self.showWork()
                    } else { NSApp.reply(toApplicationShouldTerminate: true) }
                    return
                }
            }
        }
    }

    func stopAction() {
        guard worker != nil, workerAction == "enable", !stopping else { return }
        stopping = true
        workplace.cancel()
        try? workerInput?.fileHandleForWriting.write(contentsOf: Data("stop\n".utf8))
        updateUI()
    }

    func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    func appleQuote(_ value: String) -> String { "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\"" }

    func install(remove: Bool) {
        guard canStartOperation else {
            lastError = "Сначала завершите существующий сеанс разделения."; updateUI(); return
        }
        if !remove && (installedAwaitingCheck || (state["service"] as? [String: Any])?["current"] as? Bool == true) {
            runTask("health"); return
        }
        if remove {
            let question = NSAlert()
            question.messageText = "Удалить системный помощник?"
            question.informativeText = "Удаляется только наша служба. FortiClient, профиль и отчёты сохранятся."
            question.addButton(withTitle: "Удалить")
            question.addButton(withTitle: "Отмена")
            if question.runModal() != .alertFirstButtonReturn { return }
        }
        // The wizard already explains installation. The next prompt is the OS's
        // real authorization dialog; no extra password or duplicate confirmation.
        configuring = true
        lastError = ""
        updateUI()
        let installerCode = "import sys; sys.path.insert(0, sys.argv.pop(1)); import install_helper; install_helper.main()"
        var command = shellQuote(resources.appendingPathComponent("runtime/bin/python3.12").path) + " -I -B -c " + shellQuote(installerCode) + " " + shellQuote(resources.path)
        command += " --source " + shellQuote(resources.path) + " --uid " + String(getuid())
        if remove { command += " --remove" }
        let script = "do shell script " + appleQuote(command) + " with administrator privileges with prompt " + appleQuote("Forti Split: настройка системного доступа")
        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", script]
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            var message = ""
            var code: Int32 = 1
            do {
                try process.run()
                message = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                process.waitUntilExit()
                code = process.terminationStatus
            } catch { message = error.localizedDescription }
            let resultText = message
            let resultCode = code
            DispatchQueue.main.async {
                self.configuring = false
                self.logText = String(resultText.suffix(16000))
                if resultCode != 0 {
                    self.lastError = WorkplaceResult.error(action: "install", exit: resultCode, output: resultText)
                }
                if resultCode == 0 { self.installedAwaitingCheck = !remove }
                self.refresh()
                self.updateUI()
                if resultCode == 0 && !remove { self.runTask("health") }
            }
        }
    }

    @objc func importProfile() {
        guard canStartOperation else { return }
        let panel = NSOpenPanel()
        panel.title = "Выберите приватный рабочий профиль"
        panel.message = "Нужен JSON-файл из внутреннего канала. Пароли и MFA в профиль не входят."
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let file = panel.url { runTask("import-profile", profile: file) }
    }
    @objc func recoverAction() { runTask("recover") }
    @objc func healthAction() { runTask("health") }
    @objc func removeHelper() { install(remove: true) }
    @objc func openReports() {
        let folder = dataRoot.appendingPathComponent("diagnostics", isDirectory: true)
        NSWorkspace.shared.open(folder)
    }
    func findForti() -> URL? {
        if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.fortinet.FortiClient") { return url }
        for url in [URL(fileURLWithPath: "/Applications/FortiClient.app"),
                    FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/FortiClient.app")] {
            if FileManager.default.fileExists(atPath: url.path) { return url }
        }
        return nil
    }
    func openForti() {
        guard let url = findForti() else {
            lastError = "FortiClient не найден. Установите официальный клиент по правилам организации."
            workplace.cancel()
            updateUI()
            return
        }
        fortiURL = url
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration()) { _, error in
            if let error = error {
                DispatchQueue.main.async { self.workplace.cancel(); self.recordError("FortiClient не открылся. Проверьте установку клиента.", error); self.updateUI() }
            }
        }
    }

    func advanceWorkplace() {
        guard !preview else { return }
        let active = ownsActiveSession
        let stage = (state["flow"] as? [String: Any])?["stage"] as? String ?? "unavailable"
        let effect = workplace.next(stage: stage, active: active, ownsSession: workerAction == "enable" && worker != nil,
                                    busy: worker != nil || configuring)
        switch effect {
        case "health", "prepare", "enable": runTask(effect!)
        case "open-forti": openForti()
        case "launch": launchWorkplaceApps()
        case "timeout": lastError = "Время ожидания VPN истекло. Маршруты автоматически не включались. Завершите вход и нажмите «Начать работу» снова."
        case "blocked":
            lastError = "Запуск остановлен. Выполните действие, указанное выше."
        default: break
        }
        updateUI()
    }

    func launchWorkplaceApps() {
        // Called once per user-requested run, only for our own confirmed active session.
        guard !preview, ownsActiveSession else { return }
        if preferences.hideForti {
            let running = NSRunningApplication.runningApplications(withBundleIdentifier: "com.fortinet.FortiClient")
            if let app = running.first, !app.hide() {
                launchNotice = "FortiClient не удалось скрыть; это не мешает работе."
            }
        }
        if preferences.launchTrueConf {
            if let app = findApp(identifier: "org.trueconf.client", names: ["TrueConf Client", "TrueConf"]) {
                openWorkApp(app)
            } else { lastError = "TrueConf не найден. Разделение работает; установите клиент или отключите его автозапуск в настройках." }
        }
        if preferences.launchRDP {
            let file = URL(fileURLWithPath: preferences.rdpPath)
            do {
                try preferences.validate()
                let info = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                guard !preferences.rdpPath.isEmpty, info.isRegularFile == true, info.isSymbolicLink != true else {
                    throw NSError(domain: "Workplace", code: 4)
                }
                guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.microsoft.rdc.macos") else {
                    throw NSError(domain: "Workplace", code: 5, userInfo: [NSLocalizedDescriptionKey: "Windows App не найдена."])
                }
                NSWorkspace.shared.open([file], withApplicationAt: app, configuration: NSWorkspace.OpenConfiguration()) { _, error in
                    if let error = error { DispatchQueue.main.async { self.recordError("RDP не открылся. Проверьте файл и Windows App в настройках.", error); self.updateUI() } }
                }
            } catch {
                lastError = "Не удалось открыть выбранный RDP-файл. Разделение работает. Проверьте файл и Windows App на вкладке настроек."
            }
        }
        updateUI()
    }

    func findApp(identifier: String, names: [String]) -> URL? {
        if let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: identifier) { return app }
        for parent in [URL(fileURLWithPath: "/Applications"), FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications")] {
            for name in names {
                let app = parent.appendingPathComponent(name + ".app")
                if FileManager.default.fileExists(atPath: app.path) { return app }
            }
        }
        return nil
    }

    func openWorkApp(_ app: URL) {
        NSWorkspace.shared.openApplication(at: app, configuration: NSWorkspace.OpenConfiguration()) { _, error in
            if let error = error { DispatchQueue.main.async { self.recordError("Приложение не открылось. Проверьте его установку.", error); self.updateUI() } }
        }
    }

    func syncPreferences() {
        rdpCheck.state = preferences.launchRDP ? .on : .off
        wizardRDP.state = rdpCheck.state
        trueConfCheck.state = preferences.launchTrueConf ? .on : .off
        wizardTrueConf.state = trueConfCheck.state
        hideFortiCheck.state = preferences.hideForti ? .on : .off
        wizardHideForti.state = hideFortiCheck.state
        rdpLabel.stringValue = preferences.rdpPath.isEmpty ? "RDP-файл не выбран" : URL(fileURLWithPath: preferences.rdpPath).lastPathComponent
        rdpLabel.toolTip = preferences.rdpPath
        if !preview { loginCheck.state = SMAppService.mainApp.status == .enabled ? .on : .off }
        settingsError.stringValue = lastError
        settingsError.isHidden = settingsError.stringValue.isEmpty
    }

    @discardableResult func persistPreferences() -> Bool {
        guard !preview else { return true }
        do { try preferences.save(settingsURL); preferencesError = false; syncPreferences(); return true }
        catch { preferencesError = true; recordError("Настройки не сохранены. Проверьте выбранные файлы и доступ к каталогу приложения.", error); syncPreferences(); updateUI(); return false }
    }

    @objc func preferenceChanged(_ sender: NSButton) {
        guard canStartOperation && !workplace.requested else { syncPreferences(); return }
        if sender === rdpCheck || sender === wizardRDP { preferences.launchRDP = sender.state == .on }
        if sender === trueConfCheck || sender === wizardTrueConf { preferences.launchTrueConf = sender.state == .on }
        if sender === hideFortiCheck || sender === wizardHideForti { preferences.hideForti = sender.state == .on }
        persistPreferences(); syncPreferences(); updateUI()
    }

    @objc func selectRDP() {
        guard canStartOperation && !workplace.requested else { return }
        let panel = NSOpenPanel()
        panel.title = "Выберите доверенный файл подключения RDP"
        panel.message = "Файл открывается только через Windows App. Пароли и MFA наше приложение не читает."
        panel.allowedContentTypes = [UTType(filenameExtension: "rdp") ?? .data]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let file = panel.url, file.pathExtension.lowercased() == "rdp" {
            preferences.rdpPath = file.path
            persistPreferences(); syncPreferences(); updateUI()
        }
    }

    @objc func saveSettings() { lastError = ""; persistPreferences(); syncPreferences(); updateUI() }
    @objc func loginChanged() {
        guard !preview else { return }
        do {
            let userApplications = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications").path + "/"
            guard Bundle.main.bundleURL.path.hasPrefix("/Applications/") || Bundle.main.bundleURL.path.hasPrefix(userApplications) else {
                throw NSError(domain: "Workplace", code: 6, userInfo: [NSLocalizedDescriptionKey: "Сначала перенесите приложение в постоянную папку «Программы». Затем включите автозапуск."])
            }
            if loginCheck.state == .on { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
            if SMAppService.mainApp.status == .requiresApproval {
                lastError = "Разрешите автозапуск Forti Split в настройках macOS → Основные → Объекты входа."
            }
        } catch { recordError("Автозапуск не изменён. Проверьте «Объекты входа» в настройках macOS.", error) }
        syncPreferences(); updateUI()
    }

    func buildStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem?.button?.image = NSImage(systemSymbolName: "network", accessibilityDescription: "Forti Split")
        let menu = NSMenu()
        for (title, selector) in [("Открыть Forti Split", #selector(showWork)), ("Начать работу", #selector(primaryAction)), ("Настройки…", #selector(showSettings))] {
            let item = NSMenuItem(title: title, action: selector, keyEquivalent: "")
            item.target = self; menu.addItem(item)
            if selector == #selector(primaryAction) { statusAction = item }
        }
        menu.addItem(.separator())
        menu.addItem(withTitle: "Выйти с завершением разделения", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "")
        statusItem?.menu = menu
    }

    @objc func showWork() {
        tabs.selectTabViewItem(at: 0)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    @objc func selectWorkTab() { tabs.selectTabViewItem(at: 0) }
    @objc func selectSettingsTab() { tabs.selectTabViewItem(at: 1) }
    @objc func showSettings() {
        tabs.selectTabViewItem(at: 1)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    func tabView(_ tabView: NSTabView, didSelect tabViewItem: NSTabViewItem?) {
        let workSelected = tabViewItem?.identifier as? String == "work"
        workTabButton.title = workSelected ? "● Работа" : "Работа"
        settingsTabButton.title = workSelected ? "Настройки" : "● Настройки"
        window.contentView?.layoutSubtreeIfNeeded()
        if let scroll = tabViewItem?.view?.subviews.first as? NSScrollView {
            scroll.documentView?.layoutSubtreeIfNeeded()
            scroll.contentView.scroll(to: .zero)
            scroll.reflectScrolledClipView(scroll.contentView)
        }
    }
    func recordError(_ message: String, _ error: Error) {
        logText = String((logText + "\n" + error.localizedDescription).suffix(16000))
        lastError = message
    }

    @objc func showLog() {
        alert("Последняя операция", logText.isEmpty ? (lastError.isEmpty ? "Операций ещё не было. Отчёты остаются только на этом Mac." : lastError) : String(logText.suffix(6000)))
    }
    func alert(_ title: String, _ detail: String) {
        let box = NSAlert(); box.messageText = title; box.informativeText = detail; box.runModal()
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool { sender.orderOut(nil); return false }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showWork(); return false
    }
    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if preview { return .terminateNow }
        workplace.cancel()
        if configuring { alert("Дождитесь настройки", "Закройте системный запрос или дождитесь завершения установки."); return .terminateCancel }
        guard worker != nil else { return .terminateNow }
        let question = NSAlert()
        question.messageText = "Завершить операцию и закрыть приложение?"
        question.informativeText = "Если выполняется разделение, дождитесь отката маршрутов."
        question.addButton(withTitle: "Завершить и закрыть")
        question.addButton(withTitle: "Оставить открытым")
        if question.runModal() != .alertFirstButtonReturn { return .terminateCancel }
        pendingQuit = true
        if workerAction == "enable" { stopAction() }
        return .terminateLater
    }

    func setPreview(stage: String) {
        let ready = stage != "profile"
        preferences.setupComplete = ready
        state = ["flow": ["stage": stage, "step": ready ? 4 : 1,
                          "title": ready ? "Можно включить разделение" : "Выберите рабочий профиль",
                          "detail": ready ? "Интернет пойдёт напрямую, рабочие IPv4 — через VPN. После включения проверьте рабочий стол и звонок. Оставьте это окно открытым во время работы." : "Получите приватный JSON-файл через внутренний канал. Выберите его один раз — настройки останутся только на этом Mac. Пароли и MFA в файл не входят.",
                          "primary_title": ready ? "Включить разделение" : "Выбрать файл профиля…",
                          "action": ready ? "enable" : "import-profile", "blocked": false],
                 "service": ["current": ready]]
        updateUI()
    }

    func savePreview() {
        guard let index = CommandLine.arguments.firstIndex(of: "--preview"), CommandLine.arguments.count > index + 1,
              let view = window.contentView, let image = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { NSApp.terminate(nil); return }
        view.layoutSubtreeIfNeeded()
        view.cacheDisplay(in: view.bounds, to: image)
        if let data = image.representation(using: .png, properties: [:]) {
            try? data.write(to: URL(fileURLWithPath: CommandLine.arguments[index + 1]))
        }
        NSApp.terminate(nil)
    }

    func runUITests() {
        var checks: [String: Bool] = [:]
        setPreview(stage: "profile")
        state["session"] = NSNull()
        checks["json_null_session_allows_wizard"] = canStartOperation
        checks["single_wizard_primary"] = primary.title == "Выбрать файл профиля…" && primary.isEnabled
        checks["separate_settings_tab"] = tabs.numberOfTabViewItems == 2 && tabs.tabViewItems[1].label == "Настройки"
        checks["four_readable_steps"] = stepLabels.count == 4 && detailLabel.font!.pointSize >= 15
        showSettings()
        checks["settings_tab_selects"] = tabs.selectedTabViewItem === tabs.tabViewItems[1]
        window.contentView!.layoutSubtreeIfNeeded()
        checks["settings_content_is_laid_out"] = (settingsContent?.frame.width ?? 0) > 300 && (settingsContent?.frame.height ?? 0) > 300
        showWork()
        checks["work_tab_selects"] = tabs.selectedTabViewItem === tabs.tabViewItems[0]
        setPreview(stage: "ready")
        checks["ready_primary"] = primary.title == "Начать работу" && setupOptions.isHidden && steps.isHidden
        checks["ready_copy_has_no_legacy_duration"] = !detailLabel.stringValue.contains("30") && !detailLabel.stringValue.contains("минут")
        if let name = Bundle.main.object(forInfoDictionaryKey: "CFBundleIconFile") as? String,
           let url = Bundle.main.url(forResource: name, withExtension: nil),
           let icon = NSImage(contentsOf: url) {
            checks["bundled_application_icon"] = icon.isValid && icon.size.width > 0
        } else { checks["bundled_application_icon"] = false }
        worker = Process(); workerAction = "enable"; state["session"] = ["state": "active"]; updateUI()
        checks["one_active_stop_action"] = primary.title == "Завершить работу" && primary.isEnabled
        checks["active_blocks_profile_and_recovery"] = !importButton.isEnabled && !recoverButton.isEnabled
        checks["active_session_blocks_actions"] = !canStartOperation
        let oldWorker = worker
        checks["window_close_hides_without_stopping"] = !windowShouldClose(window) && worker === oldWorker && !stopping
        window.makeKeyAndOrderFront(nil)
        stopping = true; updateUI()
        checks["no_duplicate_stop"] = !primary.isEnabled
        stopping = false; worker = nil; workerAction = ""; state.removeValue(forKey: "session")
        configuring = true; updateUI()
        checks["system_authorization_is_explicit"] = !primary.isEnabled && statusLabel.stringValue.contains("macOS")
        configuring = false
        let marker = "FORTI_SPLIT_RESULT {\"schema\":1,\"action\":\"enable\",\"pid\":123,\"outcome\":\"connection_ended\"}"
        checks["disconnect_uses_structured_own_result"] = WorkplaceResult.outcome(output: "private report\n" + marker + "\n", pid: 123, exit: 2) == "connection_ended"
        checks["foreign_result_rejected"] = WorkplaceResult.outcome(output: marker, pid: 456, exit: 2) == "failed"
        checks["rollback_failure_never_hidden"] = WorkplaceResult.outcome(output: marker, pid: 123, exit: 3) == "recovery_required"
        checks["raw_output_never_becomes_user_error"] = WorkplaceResult.error(action: "enable", exit: 2, output: String(repeating: "/private/report/", count: 500)).count < 160
        checks["cancelled_authorization_is_not_bad_password"] = WorkplaceResult.error(action: "install", exit: 1, output: "execution error: User canceled. (-128)").contains("отменено")
        checks["installer_failure_is_not_password_failure"] = !WorkplaceResult.error(action: "install", exit: 1, output: "Traceback...").contains("Неверный пароль")
        connectionEnded = true; updateUI()
        checks["disconnect_offers_new_start_without_error"] = primary.title == "Начать работу" && statusLabel.stringValue == "Соединение завершено" && detailLabel.stringValue.contains("заново")
        connectionEnded = false
        state["flow"] = ["stage": "access"]; installedAwaitingCheck = true; updateUI()
        checks["installed_helper_retries_without_password"] = primary.title == "Повторить проверку доступа" && primary.isEnabled
        installedAwaitingCheck = false; setPreview(stage: "ready")
        var run = WorkplaceRun()
        checks["idle_never_changes_network"] = run.next(stage: "ready", active: false, ownsSession: false, busy: false) == nil
        let start = Date()
        run.begin(now: start)
        checks["run_health_first"] = run.next(stage: "health", active: false, ownsSession: false, busy: false, now: start) == "health"
        checks["run_prepare_before_vpn"] = run.next(stage: "network", active: false, ownsSession: false, busy: false, now: start) == "prepare"
        checks["run_opens_forti_once"] = run.next(stage: "connect", active: false, ownsSession: false, busy: false, now: start) == "open-forti" && run.next(stage: "connect", active: false, ownsSession: false, busy: false, now: start) == nil
        checks["run_no_launch_during_apply"] = run.next(stage: "ready", active: false, ownsSession: true, busy: true, now: start) == nil
        checks["run_launches_once_after_active"] = run.next(stage: "external_session", active: true, ownsSession: true, busy: true, now: start) == "launch" && run.next(stage: "external_session", active: true, ownsSession: true, busy: true, now: start) == nil
        run.cancel()
        checks["cancel_prevents_launch"] = run.next(stage: "ready", active: true, ownsSession: true, busy: false) == nil
        run.begin(now: start)
        checks["foreign_session_never_launches"] = run.next(stage: "external_session", active: true, ownsSession: false, busy: false, now: start) == "blocked" && !run.requested
        run.begin(now: start)
        checks["vpn_wait_is_bounded"] = run.next(stage: "connect", active: false, ownsSession: false, busy: false, now: start.addingTimeInterval(301)) == "timeout" && !run.requested
        for stage in ["recovery", "unsupported", "vpn_error", "disconnect", "unavailable"] {
            run.begin()
            checks["blocked_" + stage] = run.next(stage: stage, active: false, ownsSession: false, busy: false) == "blocked" && !run.requested
        }
        let defaults = WorkplacePreferences()
        checks["apps_opt_in_by_default"] = !defaults.launchRDP && !defaults.launchTrueConf && !defaults.setupComplete
        preferences.setupComplete = false; updateUI()
        checks["onboarding_offers_optional_launches"] = !setupOptions.isHidden && primary.title == "Сохранить и продолжить"
        preferences.launchRDP = true; preferences.rdpPath = ""; updateUI()
        checks["onboarding_requires_rdp_selection_if_enabled"] = primary.title == "Выбрать RDP-файл…"
        preferences = defaults; preferences.setupComplete = true; syncPreferences(); updateUI()
        do {
            var invalid = defaults; invalid.rdpPath = "https://example.com/a.rdp"
            do { try invalid.validate(); checks["rdp_rejects_url"] = false } catch { checks["rdp_rejects_url"] = true }
            invalid.rdpPath = "/tmp/script.sh"
            do { try invalid.validate(); checks["rdp_rejects_executable"] = false } catch { checks["rdp_rejects_executable"] = true }
            let folder = FileManager.default.temporaryDirectory.appendingPathComponent("forti-preferences-test-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: folder) }
            let file = folder.appendingPathComponent("settings.json")
            var saved = defaults; saved.rdpPath = "/tmp/Рабочий стол.rdp"; saved.launchRDP = true
            try saved.save(file)
            let loaded = try WorkplacePreferences.load(file)
            let permissions = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
            checks["preferences_roundtrip_private"] = loaded.rdpPath == saved.rdpPath && loaded.launchRDP && permissions?.intValue == 0o600
        } catch { checks["preferences_roundtrip_private"] = false }
        let original = window.appearance
        window.appearance = NSAppearance(named: .darkAqua)
        checks["dark_appearance"] = window.contentView!.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
        window.appearance = NSAppearance(named: .aqua)
        checks["light_appearance"] = window.contentView!.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .aqua
        window.appearance = original
        window.contentView!.layoutSubtreeIfNeeded()
        checks["resizable_window"] = window.styleMask.contains(.resizable)
        checks["shell_paths_are_quoted"] = shellQuote("a'b") == "'a'\\''b'"
        checks["apple_script_strings_are_quoted"] = appleQuote("a\"b\\c") == "\"a\\\"b\\\\c\""
        let sleeper = Process()
        sleeper.executableURL = URL(fileURLWithPath: "/bin/sleep")
        sleeper.arguments = ["10"]
        do {
            let started = Date()
            try sleeper.run()
            worker = sleeper; workerAction = "enable"
            state["session"] = ["state": "active", "pid": sleeper.processIdentifier]
            checks["autolaunch_bound_to_backend_pid"] = ownsActiveSession
            state["session"] = ["state": "active", "pid": -1]
            checks["foreign_pid_never_owned"] = !ownsActiveSession
            worker = nil; workerAction = ""; state.removeValue(forKey: "session")
            let watchdog = statusWatchdog(sleeper, after: 0.1)
            sleeper.waitUntilExit()
            watchdog.cancel()
            checks["read_only_status_watchdog"] = Date().timeIntervalSince(started) < 3 && sleeper.terminationStatus != 0
        } catch { checks["read_only_status_watchdog"] = false }
        let executable = try? Data(contentsOf: Bundle.main.executableURL!)
        let hash = executable.map { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() } ?? ""
        let result: [String: Any] = ["schema": 1, "version": Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "",
                                     "executable_sha256": hash, "checks": checks]
        if let index = CommandLine.arguments.firstIndex(of: "--ui-test"), CommandLine.arguments.count > index + 1,
           let data = try? JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: URL(fileURLWithPath: CommandLine.arguments[index + 1]))
        }
        if checks.values.contains(false) { fatalError("UI checks failed: \(checks)") }
        NSApp.terminate(nil)
    }
}

@main struct FortiSplitApp {
    static func main() {
        signal(SIGPIPE, SIG_IGN)
        umask(0o077)
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
        withExtendedLifetime(delegate) {}
    }
}
