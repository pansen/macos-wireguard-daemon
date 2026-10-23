import AppKit

// Plain AppKit start: a SwiftUI `App` needs a scene, and every scene type
// brings a window (an empty Settings window, at least) the menu bar app
// must not have.

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusBar: StatusBarController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusBar = StatusBarController(model: StatusModel())
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
// The bundle sets LSUIElement; this covers running the bare binary.
app.setActivationPolicy(.accessory)
app.run()
