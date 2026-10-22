import AppKit
import UniformTypeIdentifiers
import CryptoKit

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

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    var window: NSWindow!
    let statusLabel = NSTextField(wrappingLabelWithString: "Проверка состояния…")
    let detailLabel = NSTextField(wrappingLabelWithString: "")
    let stageLabel = NSTextField(labelWithString: "")
    let errorLabel = NSTextField(wrappingLabelWithString: "")
    let primary = NSButton(title: "Подождите…", target: nil, action: nil)
    let moreButton = NSButton(title: "Обслуживание и настройки ▸", target: nil, action: nil)
    let importButton = NSButton(title: "Заменить профиль…", target: nil, action: nil)
    let recoverButton = NSButton(title: "Восстановить маршруты", target: nil, action: nil)
    let healthButton = NSButton(title: "Проверить доступ", target: nil, action: nil)
    let reportsButton = NSButton(title: "Отчёты", target: nil, action: nil)
    let logsButton = NSButton(title: "Журнал", target: nil, action: nil)
    let progress = NSProgressIndicator()
    let extras = NSStackView()
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
        }
        fortiURL = findForti()
        buildMenu()
        buildWindow()
        if let index = CommandLine.arguments.firstIndex(of: "--appearance"), CommandLine.arguments.count > index + 1, preview {
            window.appearance = NSAppearance(named: CommandLine.arguments[index + 1] == "dark" ? .darkAqua : .aqua)
        }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if preview {
            setPreview(stage: CommandLine.arguments.contains("--preview-profile") ? "profile" : "ready")
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
        let remove = NSMenuItem(title: "Удалить системный помощник…", action: #selector(removeHelper), keyEquivalent: "")
        remove.target = self
        application.addItem(remove)
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
        let steps = stack([], vertical: false, spacing: 12)
        steps.distribution = .fillEqually
        for name in ["Профиль", "Доступ", "Сеть", "VPN"] {
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
        let content = stack([heading, statusLabel, detailLabel, errorLabel, primary], spacing: 16)
        let mainCard = card(content)
        let foot = text("IPv4 по адресам · DNS и IPv6 без изменений\nБез паролей в приложении. Оставляйте окно открытым во время разделения.", size: 13, color: .secondaryLabelColor)
        style(moreButton, action: #selector(toggleExtras))
        moreButton.setContentHuggingPriority(.required, for: .vertical)
        style(importButton, action: #selector(importProfile), help: "Замена приватного профиля. Требует остановленного сеанса и новой подготовки.")
        style(recoverButton, action: #selector(recoverAction))
        style(healthButton, action: #selector(healthAction))
        style(reportsButton, action: #selector(openReports))
        style(logsButton, action: #selector(showLog))
        let row1 = stack([importButton, healthButton], vertical: false, spacing: 12)
        let row2 = stack([recoverButton, reportsButton, logsButton], vertical: false, spacing: 12)
        extras.orientation = .vertical
        extras.alignment = .leading
        extras.spacing = 12
        for row in [row1, row2] {
            extras.addArrangedSubview(row)
            row.widthAnchor.constraint(equalTo: extras.widthAnchor).isActive = true
        }
        extras.isHidden = true
        let secondary = card(stack([moreButton, extras], spacing: 12))
        let root = stack([title, subtitle, steps, mainCard, foot, secondary], spacing: 14)
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        scroll.translatesAutoresizingMaskIntoConstraints = false
        let document = FlippedDocument()
        document.translatesAutoresizingMaskIntoConstraints = false
        root.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(root)
        scroll.documentView = document
        window.contentView!.addSubview(scroll)
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: window.contentView!.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor),
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            root.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 28),
            root.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -28),
            root.topAnchor.constraint(equalTo: document.topAnchor, constant: 26),
            root.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -26)
        ])
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
                self.state = snapshot
                if let message = snapshot["status_error"] as? String {
                    self.lastError = message
                }
                self.updateUI()
            }
        }
    }

    func updateUI() {
        let session = state["session"] as? [String: Any]
        let active = session?["state"] as? String == "active"
        let idle = worker == nil && !configuring && session == nil
        let flow = state["flow"] as? [String: Any] ?? [:]
        var stage = flow["step"] as? Int ?? 0
        statusLabel.textColor = .labelColor
        primary.isEnabled = idle && flow["blocked"] as? Bool != true
        importButton.isEnabled = idle
        recoverButton.isEnabled = idle
        healthButton.isEnabled = idle && (state["service"] as? [String: Any])?["current"] as? Bool == true
        errorLabel.stringValue = lastError
        errorLabel.isHidden = lastError.isEmpty
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
                detailLabel.stringValue = active ? "Интернет — напрямую, рабочие адреса — через VPN. Без лимита времени. Оставьте приложение открытым." : "Если проверка не пройдёт, изменения будут отменены. Можно остановить операцию с откатом."
                primary.title = active ? "Отключить разделение" : "Отменить и откатить"
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
        for (index, label) in stepLabels.enumerated() {
            let names = ["Профиль", "Доступ", "Сеть", "VPN"]
            label.stringValue = "\(index + 1 < stage ? "✓" : String(index + 1))  \(names[index])"
            label.font = .systemFont(ofSize: 13, weight: index + 1 == stage ? .semibold : .regular)
            label.textColor = index + 1 == stage ? .labelColor : .secondaryLabelColor
        }
        statusLabel.setAccessibilityLabel(statusLabel.stringValue)
        primary.setAccessibilityLabel(primary.title)
    }

    @objc func primaryAction() {
        if workerAction == "enable" && worker != nil { stopAction(); return }
        guard canStartOperation else { return }
        lastError = ""
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
        output.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            let text = String(decoding: data, as: UTF8.self)
            DispatchQueue.main.async {
                self.logText = String((self.logText + text).suffix(16000))
                self.refresh()
            }
        }
        process.terminationHandler = { item in
            DispatchQueue.main.async {
                self.workerInput?.fileHandleForWriting.closeFile()
                self.workerInput = nil
                self.worker = nil
                self.workerAction = ""
                self.stopping = false
                if item.terminationStatus != 0 && item.terminationStatus != 130 {
                    self.lastError = String(self.logText.suffix(1200))
                    if self.lastError.isEmpty { self.lastError = "Операция не завершена. Откройте журнал в разделе обслуживания." }
                }
                self.refresh()
                self.updateUI()
                if self.pendingQuit { NSApp.reply(toApplicationShouldTerminate: true); return }
                if action == "prepare" && item.terminationStatus == 0 { self.openForti() }
            }
        }
        do { try process.run(); updateUI() }
        catch {
            worker = nil
            workerInput = nil
            workerAction = ""
            lastError = error.localizedDescription
            updateUI()
        }
    }

    func stopAction() {
        guard worker != nil, workerAction == "enable", !stopping else { return }
        stopping = true
        try? workerInput?.fileHandleForWriting.write(contentsOf: Data("stop\n".utf8))
        updateUI()
    }

    func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    func appleQuote(_ value: String) -> String { "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\"" }

    func install(remove: Bool) {
        guard canStartOperation else {
            lastError = "Сначала завершите существующий сеанс разделения."; updateUI(); return
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
                    self.lastError = resultText.contains("-128") ? "Разрешение отменено. Можно повторить этот этап." : String(resultText.suffix(1200))
                }
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
    @objc func toggleExtras() {
        extras.isHidden.toggle()
        moreButton.title = extras.isHidden ? "Обслуживание и настройки ▸" : "Скрыть дополнительные действия ▾"
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
            updateUI()
            return
        }
        fortiURL = url
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration()) { _, error in
            if let error = error {
                DispatchQueue.main.async { self.lastError = error.localizedDescription; self.updateUI() }
            }
        }
    }
    @objc func showLog() {
        alert("Последняя операция", logText.isEmpty ? (lastError.isEmpty ? "Операций ещё не было. Отчёты остаются только на этом Mac." : lastError) : String(logText.suffix(6000)))
    }
    func alert(_ title: String, _ detail: String) {
        let box = NSAlert(); box.messageText = title; box.informativeText = detail; box.runModal()
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool { NSApp.terminate(nil); return false }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
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
        checks["maintenance_initially_collapsed"] = extras.isHidden
        checks["four_readable_steps"] = stepLabels.count == 4 && detailLabel.font!.pointSize >= 15
        toggleExtras()
        checks["maintenance_group_expands"] = !extras.isHidden
        toggleExtras()
        checks["maintenance_group_collapses"] = extras.isHidden
        setPreview(stage: "ready")
        checks["ready_primary"] = primary.title == "Включить разделение"
        checks["ready_copy_has_no_legacy_duration"] = !detailLabel.stringValue.contains("30") && !detailLabel.stringValue.contains("минут")
        if let name = Bundle.main.object(forInfoDictionaryKey: "CFBundleIconFile") as? String,
           let url = Bundle.main.url(forResource: name, withExtension: nil),
           let icon = NSImage(contentsOf: url) {
            checks["bundled_application_icon"] = icon.isValid && icon.size.width > 0
        } else { checks["bundled_application_icon"] = false }
        worker = Process(); workerAction = "enable"; state["session"] = ["state": "active"]; updateUI()
        checks["one_active_stop_action"] = primary.title == "Отключить разделение" && primary.isEnabled
        checks["active_blocks_profile_and_recovery"] = !importButton.isEnabled && !recoverButton.isEnabled
        checks["active_session_blocks_actions"] = !canStartOperation
        stopping = true; updateUI()
        checks["no_duplicate_stop"] = !primary.isEnabled
        stopping = false; worker = nil; workerAction = ""; state.removeValue(forKey: "session")
        configuring = true; updateUI()
        checks["system_authorization_is_explicit"] = !primary.isEnabled && statusLabel.stringValue.contains("macOS")
        configuring = false
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
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.regular)
        app.run()
        withExtendedLifetime(delegate) {}
    }
}
