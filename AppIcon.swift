// Original vector artwork. Build-time only: no image downloads or runtime tools.
import AppKit

@main struct AppIcon {
    static func render(pixels: Int) throws -> Data {
        guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels,
                                          pixelsHigh: pixels, bitsPerSample: 8,
                                          samplesPerPixel: 4, hasAlpha: true,
                                          isPlanar: false, colorSpaceName: .deviceRGB,
                                          bytesPerRow: 0, bitsPerPixel: 0),
              let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
            throw NSError(domain: "AppIcon", code: 1)
        }
        NSGraphicsContext.saveGraphicsState()
        defer { NSGraphicsContext.restoreGraphicsState() }
        NSGraphicsContext.current = context
        context.imageInterpolation = .high
        let canvas = context.cgContext
        canvas.clear(CGRect(x: 0, y: 0, width: pixels, height: pixels))
        canvas.scaleBy(x: CGFloat(pixels) / 512, y: CGFloat(pixels) / 512)

        let tile = NSBezierPath(roundedRect: NSRect(x: 24, y: 24, width: 464, height: 464),
                                xRadius: 104, yRadius: 104)
        NSGradient(starting: NSColor(srgbRed: 0.035, green: 0.20, blue: 0.47, alpha: 1),
                   ending: NSColor(srgbRed: 0.03, green: 0.66, blue: 0.66, alpha: 1))!
            .draw(in: tile, angle: 60)
        NSColor.white.withAlphaComponent(0.12).setStroke()
        tile.lineWidth = 2
        tile.stroke()

        let routes = NSBezierPath()
        routes.move(to: NSPoint(x: 126, y: 256))
        routes.line(to: NSPoint(x: 216, y: 256))
        routes.curve(to: NSPoint(x: 348, y: 350),
                     controlPoint1: NSPoint(x: 270, y: 256),
                     controlPoint2: NSPoint(x: 279, y: 350))
        routes.move(to: NSPoint(x: 216, y: 256))
        routes.curve(to: NSPoint(x: 348, y: 162),
                     controlPoint1: NSPoint(x: 270, y: 256),
                     controlPoint2: NSPoint(x: 279, y: 162))
        routes.lineWidth = 30
        routes.lineCapStyle = .round
        routes.lineJoinStyle = .round
        NSColor.white.setStroke()
        routes.stroke()

        for (x, y, color) in [
            (126.0, 256.0, NSColor.white),
            (356.0, 350.0, NSColor(srgbRed: 0.64, green: 0.98, blue: 0.84, alpha: 1)),
            (356.0, 162.0, NSColor(srgbRed: 0.68, green: 0.86, blue: 1, alpha: 1))
        ] {
            color.setFill()
            NSBezierPath(ovalIn: NSRect(x: x - 28, y: y - 28, width: 56, height: 56)).fill()
        }
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            throw NSError(domain: "AppIcon", code: 2)
        }
        return png
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            throw NSError(domain: "AppIcon", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "Expected output iconset directory"])
        }
        let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for points in [16, 32, 128, 256, 512] {
            for scale in [1, 2] {
                let suffix = scale == 2 ? "@2x" : ""
                let file = directory.appendingPathComponent("icon_\(points)x\(points)\(suffix).png")
                try render(pixels: points * scale).write(to: file, options: .atomic)
            }
        }
    }
}
