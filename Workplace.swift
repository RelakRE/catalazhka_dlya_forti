import Foundation
import Darwin

struct WorkplacePreferences: Codable {
    var schema = 1
    var setupComplete = false
    var launchRDP = false
    var rdpPath = ""
    var launchTrueConf = false
    var hideForti = true

    func validate() throws {
        guard schema == 1, rdpPath.utf8.count <= 8192,
              rdpPath.isEmpty || (rdpPath.hasPrefix("/") && !rdpPath.contains("\0") &&
                                 URL(fileURLWithPath: rdpPath).pathExtension.lowercased() == "rdp") else {
            throw NSError(domain: "Workplace", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Некорректные настройки рабочего места."])
        }
    }

    static func load(_ file: URL) throws -> WorkplacePreferences {
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(), info.st_size <= 65536 else {
            throw NSError(domain: "Workplace", code: 2)
        }
        let data = try handle.read(upToCount: 65537) ?? Data()
        guard data.count <= 65536 else { throw NSError(domain: "Workplace", code: 2) }
        let value = try JSONDecoder().decode(Self.self, from: data)
        try value.validate()
        return value
    }

    func save(_ file: URL) throws {
        try validate()
        // Atomic replacement rather than following an existing destination symlink.
        try JSONEncoder().encode(self).write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
}

// Pure intent state: no OS calls, timers, credentials or route operations here.
struct WorkplaceRun {
    private(set) var requested = false
    private(set) var launched = false
    private(set) var openedForti = false
    private var started = Date.distantPast

    mutating func begin(now: Date = Date()) {
        requested = true; launched = false; openedForti = false; started = now
    }
    mutating func cancel() { requested = false }

    mutating func next(stage: String, active: Bool, ownsSession: Bool,
                       busy: Bool, now: Date = Date()) -> String? {
        guard requested else { return nil }
        if active && ownsSession {
            guard !launched else { return nil }
            launched = true
            return "launch"
        }
        guard !busy else { return nil }
        if now.timeIntervalSince(started) > 300 { cancel(); return "timeout" }
        switch stage {
        case "health": return "health"
        case "network": return "prepare"
        case "ready": return "enable"
        case "connect":
            guard !openedForti else { return nil }
            openedForti = true
            return "open-forti"
        default: cancel(); return "blocked"
        }
    }
}
