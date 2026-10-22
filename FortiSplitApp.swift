import AppKit
import UniformTypeIdentifiers

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    var window: NSWindow!
    let titleLabel = NSTextField(labelWithString: "Forti Split")
    let statusLabel = NSTextField(labelWithString: "Проверка состояния…")
    let detailLabel = NSTextField(wrappingLabelWithString: "")
    let helperLabel = NSTextField(wrappingLabelWithString: "")
    let primary = NSButton(title: "Подготовить", target: nil, action: nil)
    let stopButton = NSButton(title: "Отключить", target: nil, action: nil)
    let installButton = NSButton(title: "Установить помощник…", target: nil, action: nil)
    let importButton = NSButton(title: "Импортировать настройки…", target: nil, action: nil)
    let progress = NSProgressIndicator()
    var state: [String: Any] = [:]
    var refreshing = false
    var worker: Process?
    var workerInput: Pipe?
    var workerAction = ""
    var stopping = false
    var pendingQuit = false
    var configuring = false
    var logText = ""
    var dataRoot: URL!
    var timer: Timer?
    let resources = Bundle.main.resourceURL!
    var preview: Bool { CommandLine.arguments.contains("--preview") || CommandLine.arguments.contains("--ui-test") }

    func label(_ text: String, size: CGFloat, color: NSColor = .labelColor) -> NSTextField {
        let view = NSTextField(labelWithString: text)
        view.font = .systemFont(ofSize: size)
        view.textColor = color
        return view
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.appearance = NSAppearance(named: .aqua)
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        dataRoot = base.appendingPathComponent("Forti Split", isDirectory: true)
        if let index = CommandLine.arguments.firstIndex(of: "--data-root"), CommandLine.arguments.count > index + 1 {
            dataRoot = URL(fileURLWithPath: CommandLine.arguments[index + 1], isDirectory: true)
        }
        if !preview {
            do {
                try FileManager.default.createDirectory(at: dataRoot, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
                let config = dataRoot.appendingPathComponent("split-config.json")
                if !FileManager.default.fileExists(atPath: config.path) {
                    try FileManager.default.copyItem(at: resources.appendingPathComponent("split-config.json"), to: config)
                }
            } catch { alert("Не удалось создать каталог данных", error.localizedDescription) }
        }
        buildMenu()
        buildWindow()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if preview {
            state = ["service": ["installed": true, "current": true], "profile": ["ready": true], "prepared": true,
                     "vpn": ["interface": "utun6"]]
            updateUI()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                if CommandLine.arguments.contains("--ui-test") { self.runUITests() } else { self.savePreview() }
            }
        } else {
            refresh()
            timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in self?.refresh() }
        }
    }

    func buildMenu() {
        let menu = NSMenu()
        let root = NSMenuItem()
        menu.addItem(root)
        let appMenu = NSMenu()
        root.submenu = appMenu
        let remove = NSMenuItem(title: "Удалить системный помощник…", action: #selector(removeHelper), keyEquivalent: "")
        remove.target = self
        appMenu.addItem(remove)
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Завершить Forti Split", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        NSApp.mainMenu = menu
    }

    func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 570, height: 486),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Forti Split"
        window.delegate = self
        window.center()
        let content = window.contentView!
        content.wantsLayer = true
        content.layer?.backgroundColor = NSColor(calibratedWhite: 0.96, alpha: 1).cgColor
        titleLabel.font = .systemFont(ofSize: 27, weight: .semibold)
        titleLabel.frame = NSRect(x: 28, y: 369, width: 440, height: 38)
        content.addSubview(titleLabel)
        let subtitle = label("Рабочий VPN и обычный интернет — одновременно", size: 13, color: .secondaryLabelColor)
        subtitle.frame = NSRect(x: 29, y: 344, width: 510, height: 24)
        content.addSubview(subtitle)
        let box = NSBox(frame: NSRect(x: 26, y: 196, width: 518, height: 134))
        box.boxType = .custom
        box.cornerRadius = 12
        box.fillColor = .controlBackgroundColor
        box.borderColor = .separatorColor
        box.borderWidth = 0.5
        content.addSubview(box)
        statusLabel.font = .systemFont(ofSize: 18, weight: .semibold)
        statusLabel.frame = NSRect(x: 44, y: 282, width: 460, height: 28)
        content.addSubview(statusLabel)
        detailLabel.font = .systemFont(ofSize: 13)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.frame = NSRect(x: 44, y: 209, width: 462, height: 67)
        content.addSubview(detailLabel)
        primary.frame = NSRect(x: 24, y: 143, width: 350, height: 38)
        primary.bezelStyle = .rounded
        primary.controlSize = .large
        primary.keyEquivalent = "\r"
        primary.target = self
        primary.action = #selector(primaryAction)
        content.addSubview(primary)
        stopButton.frame = NSRect(x: 385, y: 143, width: 160, height: 38)
        stopButton.bezelStyle = .rounded
        stopButton.controlSize = .large
        stopButton.target = self
        stopButton.action = #selector(stopAction)
        content.addSubview(stopButton)
        progress.style = .spinning
        progress.controlSize = .small
        progress.frame = NSRect(x: 520, y: 286, width: 16, height: 16)
        progress.isDisplayedWhenStopped = false
        content.addSubview(progress)
        helperLabel.font = .systemFont(ofSize: 11)
        helperLabel.textColor = .secondaryLabelColor
        helperLabel.frame = NSRect(x: 31, y: 98, width: 495, height: 34)
        content.addSubview(helperLabel)
        installButton.frame = NSRect(x: 25, y: 63, width: 210, height: 28)
        installButton.bezelStyle = .rounded
        installButton.target = self
        installButton.action = #selector(installHelper)
        content.addSubview(installButton)
        let report = NSButton(title: "Отчёты", target: self, action: #selector(openReports))
        report.frame = NSRect(x: 237, y: 63, width: 94, height: 28)
        report.bezelStyle = .rounded
        content.addSubview(report)
        let recover = NSButton(title: "Восстановить", target: self, action: #selector(recoverAction))
        recover.frame = NSRect(x: 335, y: 63, width: 116, height: 28)
        recover.bezelStyle = .rounded
        content.addSubview(recover)
        let logs = NSButton(title: "Журнал", target: self, action: #selector(showLog))
        logs.frame = NSRect(x: 451, y: 63, width: 94, height: 28)
        logs.bezelStyle = .rounded
        content.addSubview(logs)
        let foot = label("IPv4 · DNS и IPv6 без изменений · MFA вводится только в FortiClient", size: 10, color: .tertiaryLabelColor)
        foot.frame = NSRect(x: 31, y: 22, width: 510, height: 25)
        content.addSubview(foot)
        for view in content.subviews { view.frame.origin.y += 48 }
        importButton.frame = NSRect(x: 25, y: 22, width: 225, height: 30)
        importButton.bezelStyle = .rounded
        importButton.target = self
        importButton.action = #selector(importProfile)
        content.addSubview(importButton)
        let privacy = label("Рабочий профиль хранится только на вашем Mac", size: 10, color: .secondaryLabelColor)
        privacy.frame = NSRect(x: 255, y: 26, width: 290, height: 22)
        content.addSubview(privacy)
    }

    func backend(_ action: String) -> Process {
        let process = Process()
        process.executableURL = resources.appendingPathComponent("runtime/bin/python3.12")
        let code = "import sys,runpy; sys.path.insert(0, sys.argv.pop(1)); runpy.run_module('gui_backend', run_name='__main__')"
        process.arguments = ["-I", "-B", "-c", code, resources.path,
                             "--data-root", dataRoot.path, action]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        return process
    }

    func refresh() {
        if refreshing { return }
        refreshing = true
        DispatchQueue.global(qos: .utility).async {
            let process = self.backend("status")
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            process.standardInput = FileHandle.nullDevice
            var value: [String: Any] = [:]
            do {
                try process.run()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                value = (try JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
            } catch { value = ["status_error": error.localizedDescription] }
            let snapshot = value
            DispatchQueue.main.async {
                self.refreshing = false
                self.state = snapshot
                self.updateUI()
            }
        }
    }

    func updateUI() {
        let service = state["service"] as? [String: Any] ?? [:]
        let installed = service["installed"] as? Bool == true && service["current"] as? Bool == true
        let vpn = state["vpn"] is [String: Any]
        let prepared = state["prepared"] as? Bool == true
        let session = state["session"] as? [String: Any]
        let active = session?["state"] as? String == "active"
        let profileReady = (state["profile"] as? [String: Any])?["ready"] as? Bool == true
        importButton.isEnabled = worker == nil && session == nil && !configuring
        primary.isEnabled = worker == nil && session == nil && !configuring
        stopButton.isEnabled = worker != nil && workerAction == "enable" && !stopping
        installButton.isEnabled = worker == nil && session == nil && !configuring
        installButton.isHidden = installed
        installButton.title = service["installed"] as? Bool == true ? "Обновить помощник…" : "Установить помощник…"
        helperLabel.stringValue = installed ? "Системный помощник готов. Повторный пароль администратора не нужен." :
            "Для кнопки включения установите помощник: одно системное разрешение администратора. Пароль не сохраняется."
        statusLabel.textColor = .labelColor
        if configuring {
            statusLabel.stringValue = "Настройка системного помощника…"
            detailLabel.stringValue = "Разрешение запрашивает сама macOS. Не закрывайте приложение до завершения установки."
            primary.title = "Подождите…"
            progress.startAnimation(nil)
        } else if worker != nil {
            if stopping {
                statusLabel.stringValue = "Отключение и откат…"
                detailLabel.stringValue = "Дождитесь подтверждения удаления собственных маршрутов. FortiClient не отключается приложением."
            } else if workerAction == "enable" && active {
                statusLabel.stringValue = "●  Разделение включено"
                statusLabel.textColor = .systemGreen
                detailLabel.stringValue = "Интернет — напрямую, рабочие адреса — через FortiClient. Без лимита времени. Оставьте приложение открытым."
            } else {
                statusLabel.stringValue = workerAction == "enable" ? "Включение и проверка…" : workerAction == "health" ? "Проверка помощника…" : "Подготовка / восстановление…"
                detailLabel.stringValue = "Проверяются состояние сети, маршруты и результаты операций."
            }
            primary.title = active ? "Включено без лимита" : "Подождите…"
            if !active || stopping { progress.startAnimation(nil) } else { progress.stopAnimation(nil) }
        } else if session != nil {
            progress.stopAnimation(nil)
            statusLabel.stringValue = "Разделение работает в другом окне"
            detailLabel.stringValue = "Завершите существующий сеанс в Terminal или другом экземпляре, затем используйте приложение."
        } else {
            progress.stopAnimation(nil)
            if state["latest_status"] as? String == "rollback_unconfirmed" {
                statusLabel.stringValue = "Нужно восстановление"
                statusLabel.textColor = .systemRed
                detailLabel.stringValue = "Откат прошлого сеанса не подтверждён. Нажмите «Восстановить» и проверьте отчёт."
                primary.isEnabled = false
            } else if state.isEmpty || state["status_error"] != nil {
                statusLabel.stringValue = "Проверка приложения…"
                detailLabel.stringValue = "Если состояние не обновляется, откройте журнал и проверьте комплектность приложения."
                primary.isEnabled = false
            } else if !profileReady {
                statusLabel.stringValue = "Нужен рабочий профиль"
                detailLabel.stringValue = "Получите JSON-профиль по внутреннему каналу и нажмите «Импортировать настройки…». Публичная сборка не содержит рабочих адресов."
                primary.title = "Импортировать настройки…"
            } else if !installed {
                statusLabel.stringValue = "Первый запуск"
                detailLabel.stringValue = "Разрешите установку узкого системного помощника. Далее управление — кнопками, без Terminal и постоянного ввода пароля."
                primary.title = "Настроить доступ…"
            } else if vpn && prepared {
                statusLabel.stringValue = state["rollback_ok"] as? Bool == true ? "Отключено · откат подтверждён" : "Готово к включению"
                detailLabel.stringValue = "FortiClient подключён. Можно включить разделение; сеть и HTTPS будут автоматически проверены."
                primary.title = "Включить разделение"
            } else if vpn {
                statusLabel.stringValue = "Нужна подготовка без VPN"
                detailLabel.stringValue = "Отключите FortiClient один раз и нажмите «Подготовить». Данные текущей сети пока не проверены."
                primary.title = "Сначала отключите FortiClient"
                primary.isEnabled = false
            } else if prepared {
                statusLabel.stringValue = "Подготовка готова"
                detailLabel.stringValue = "Откройте FortiClient, подключите рабочий VPN и пройдите MFA. Затем вернитесь сюда — появится кнопка включения."
                primary.title = "Открыть FortiClient"
            } else {
                statusLabel.stringValue = "VPN отключён"
                detailLabel.stringValue = "Подготовьте текущую сеть без VPN. Затем подключите FortiClient обычным способом. Внутри Windows VPN должен быть отключён."
                primary.title = "Подготовить"
            }
        }
    }

    @objc func primaryAction() {
        if (state["profile"] as? [String: Any])?["ready"] as? Bool != true { importProfile(); return }
        let service = state["service"] as? [String: Any] ?? [:]
        if service["installed"] as? Bool != true || service["current"] as? Bool != true { installHelper(); return }
        if state["vpn"] is [String: Any] { runTask("enable"); return }
        if state["prepared"] as? Bool == true { openForti(); return }
        runTask("prepare")
    }

    func runTask(_ action: String, profile: URL? = nil) {
        guard worker == nil, !configuring else { return }
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
        output.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            let text = String(decoding: data, as: UTF8.self)
            DispatchQueue.main.async { self.logText += text; self.refresh() }
        }
        process.terminationHandler = { item in
            DispatchQueue.main.async {
                self.workerInput?.fileHandleForWriting.closeFile()
                self.workerInput = nil
                self.worker = nil
                self.stopping = false
                self.refresh()
                if self.pendingQuit { NSApp.reply(toApplicationShouldTerminate: true); return }
                if item.terminationStatus != 0 && item.terminationStatus != 130 {
                    self.alert("Операция не завершена", self.logText.isEmpty ? "Откройте отчёт для подробностей." : String(self.logText.suffix(2400)))
                } else if action == "prepare" && item.terminationStatus == 0 { self.openForti() }
            }
        }
        do { try process.run(); updateUI() }
        catch { worker = nil; workerInput = nil; alert("Не удалось запустить проверку", error.localizedDescription); updateUI() }
    }

    @objc func stopAction() {
        guard worker != nil, workerAction == "enable", !stopping else { return }
        stopping = true
        try? workerInput?.fileHandleForWriting.write(contentsOf: Data("stop\n".utf8))
        updateUI()
    }

    func shellQuote(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    func appleQuote(_ text: String) -> String { "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\"" }

    func install(remove: Bool) {
        guard worker == nil, !configuring, state["session"] as? [String: Any] == nil else {
            alert("Сначала завершите разделение", "Установка/удаление помощника не выполняется во время активного сеанса."); return
        }
        let question = NSAlert()
        question.messageText = remove ? "Удалить системный помощник?" : "Разрешить системный помощник Forti Split?"
        question.informativeText = remove ? "Будет удалена только наша служба. FortiClient, исходники и отчёты сохранятся." :
            "Будет установлена отдельная root-служба в /Library/PrivilegedHelperTools и LaunchDaemons. Она принимает только ограниченные операции маршрутизации от вашей учётной записи. Пароль потребуется один раз в системном окне; sudoers и пароль не сохраняются."
        question.addButton(withTitle: remove ? "Удалить" : "Установить")
        question.addButton(withTitle: "Отмена")
        if question.runModal() != .alertFirstButtonReturn { return }
        configuring = true
        updateUI()
        var command = shellQuote(resources.appendingPathComponent("runtime/bin/python3.12").path) + " -I -B " + shellQuote(resources.appendingPathComponent("install_helper.py").path)
        command += " --source " + shellQuote(resources.path) + " --uid " + String(getuid())
        if remove { command += " --remove" }
        let script = "do shell script " + appleQuote(command) + " with administrator privileges with prompt " + appleQuote("Forti Split: однократная настройка системного помощника")
        installButton.isEnabled = false
        primary.isEnabled = false
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
            let text = message
            let result = code
            DispatchQueue.main.async {
                self.configuring = false
                if result != 0 { self.alert("Настройка не завершена", text) }
                else { self.logText = text }
                self.refresh()
                if result == 0 && !remove { self.runTask("health") }
            }
        }
    }

    @objc func installHelper() { install(remove: false) }
    @objc func importProfile() {
        guard worker == nil, !configuring, state["session"] as? [String: Any] == nil else {
            alert("Сначала завершите разделение", "Профиль нельзя менять во время активного сеанса."); return
        }
        let panel = NSOpenPanel()
        panel.title = "Импортировать приватный рабочий профиль"
        panel.message = "Файл останется локальным. Не загружайте его в публичный репозиторий."
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let file = panel.url { runTask("import-profile", profile: file) }
    }
    @objc func removeHelper() { install(remove: true) }
    @objc func recoverAction() { runTask("recover") }
    @objc func openReports() {
        let folder = dataRoot.appendingPathComponent("diagnostics", isDirectory: true)
        if !FileManager.default.fileExists(atPath: folder.path) { try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true) }
        NSWorkspace.shared.open(folder)
    }
    func openForti() { NSWorkspace.shared.open(URL(fileURLWithPath: "/Applications/FortiClient.app")) }
    @objc func showLog() { alert("Последняя операция", logText.isEmpty ? "Операций ещё не было. Полные результаты доступны в папке «Отчёты»." : String(logText.suffix(5000))) }
    func alert(_ title: String, _ detail: String) {
        let box = NSAlert(); box.messageText = title; box.informativeText = detail; box.runModal()
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool { NSApp.terminate(nil); return false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if configuring { alert("Дождитесь настройки", "Системная установка ещё не завершена."); return .terminateCancel }
        guard worker != nil else { return .terminateNow }
        let question = NSAlert()
        question.messageText = "Завершить операцию и закрыть приложение?"
        question.informativeText = "Активное разделение будет отключено с откатом. Дождитесь завершения операции."
        question.addButton(withTitle: "Завершить и закрыть")
        question.addButton(withTitle: "Оставить открытым")
        if question.runModal() != .alertFirstButtonReturn { return .terminateCancel }
        pendingQuit = true
        if workerAction == "enable" { stopAction() }
        return .terminateLater
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
        state = ["service": ["installed": false], "profile": ["ready": false]]; updateUI()
        checks["public_build_requires_profile"] = primary.title == "Импортировать настройки…" && importButton.isEnabled
        state["profile"] = ["ready": true]; updateUI()
        checks["first_run_requires_explicit_setup"] = primary.title == "Настроить доступ…" && !installButton.isHidden
        state = ["service": ["installed": true, "current": true], "profile": ["ready": true]]; updateUI()
        checks["prepare_without_vpn"] = primary.title == "Подготовить" && primary.isEnabled
        state["prepared"] = true; updateUI()
        checks["open_forti_after_preparation"] = primary.title == "Открыть FortiClient"
        state["vpn"] = ["interface": "utun6"]; updateUI()
        checks["enable_only_after_vpn"] = primary.title == "Включить разделение" && primary.isEnabled
        worker = Process(); workerAction = "enable"; state["session"] = ["state": "active"]; updateUI()
        checks["active_allows_stop"] = stopButton.isEnabled && !primary.isEnabled && detailLabel.stringValue.contains("Без лимита")
        checks["active_blocks_import"] = !importButton.isEnabled
        stopping = true; updateUI()
        checks["no_duplicate_stop"] = !stopButton.isEnabled
        stopping = false; worker = nil; state.removeValue(forKey: "session")
        state["rollback_ok"] = true; updateUI()
        checks["confirmed_rollback_visible"] = statusLabel.stringValue.contains("откат подтверждён")
        state["latest_status"] = "rollback_unconfirmed"; updateUI()
        checks["unconfirmed_rollback_blocks_enable"] = !primary.isEnabled
        checks["shell_paths_are_quoted"] = shellQuote("a'b") == "'a'\\''b'"
        if let index = CommandLine.arguments.firstIndex(of: "--ui-test"), CommandLine.arguments.count > index + 1,
           let data = try? JSONSerialization.data(withJSONObject: checks, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: URL(fileURLWithPath: CommandLine.arguments[index + 1]))
        }
        if checks.values.contains(false) { fatalError("UI checks failed: \(checks)") }
        NSApp.terminate(nil)
    }
}

@main struct FortiSplitApp {
    static func main() {
        signal(SIGPIPE, SIG_IGN)
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
        withExtendedLifetime(delegate) {}
    }
}
