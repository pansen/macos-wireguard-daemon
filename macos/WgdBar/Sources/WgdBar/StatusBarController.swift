import AppKit
import Observation
import SwiftUI

/// The status item and its flyout. AppKit instead of `MenuBarExtra`, whose
/// window leaves a gap below the menu bar and has a fixed corner radius.
@MainActor
final class StatusBarController {
    private let model: StatusModel
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let panel: FlyoutPanel
    private var outsideClickMonitor: Any?

    private let loginItem = LoginItem()

    init(model: StatusModel) {
        self.model = model
        panel = FlyoutPanel(rootView: FlyoutView(model: model, loginItem: loginItem))
        panel.onSizeChange = { [weak self] in self?.positionPanel() }
        panel.onClose = { [weak self] in self?.stopMonitoringOutsideClicks() }

        if let button = statusItem.button {
            button.target = self
            button.action = #selector(togglePanel)
        }
        observeModel()
    }

    @objc private func togglePanel() {
        if panel.isVisible {
            panel.close()
        } else {
            loginItem.refresh()
            positionPanel()
            panel.makeKeyAndOrderFront(nil)
            monitorOutsideClicks()
        }
    }

    /// Centered under the status item, flush with the bottom of the menu
    /// bar, kept inside the screen.
    private func positionPanel() {
        guard let buttonWindow = statusItem.button?.window,
              let screen = buttonWindow.screen ?? NSScreen.main
        else { return }
        let anchor = buttonWindow.frame
        let size = panel.frame.size
        let visible = screen.visibleFrame
        let x = min(max(anchor.midX - size.width / 2, visible.minX + 8), visible.maxX - size.width - 8)
        panel.setFrameTopLeftPoint(NSPoint(x: x, y: anchor.minY))
    }

    private func monitorOutsideClicks() {
        // Clicks into other apps never reach this process as local events.
        outsideClickMonitor = NSEvent.addGlobalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown]
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.panel.close() }
        }
    }

    private func stopMonitoringOutsideClicks() {
        if let outsideClickMonitor {
            NSEvent.removeMonitor(outsideClickMonitor)
        }
        outsideClickMonitor = nil
    }

    private func observeModel() {
        withObservationTracking {
            updateButton()
        } onChange: { [weak self] in
            Task { @MainActor in self?.observeModel() }
        }
    }

    private func updateButton() {
        guard let button = statusItem.button else { return }
        let overall = model.overall
        let image = NSImage(systemSymbolName: overall.symbol, accessibilityDescription: overall.title)
        image?.isTemplate = true
        // Swapping the image costs a WindowServer round trip; only do it on
        // a real change.
        if button.image?.accessibilityDescription != overall.title {
            button.image = image
        }
        button.toolTip = tooltip()
    }

    private func tooltip() -> String {
        var lines = [model.overall.title]
        for line in model.snapshot?.connections ?? [] {
            lines.append("\(line.title): \(line.detail)")
        }
        if let error = model.snapshot?.error {
            lines.append(error)
        }
        return lines.joined(separator: "\n")
    }
}

/// Borderless panel with a menu-style material and slightly rounded corners.
/// It sizes itself to its SwiftUI content and keeps its top edge in place.
private final class FlyoutPanel: NSPanel {
    var onSizeChange: (() -> Void)?
    var onClose: (() -> Void)?

    init<Content: View>(rootView: Content) {
        super.init(
            contentRect: .zero,
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: true
        )
        level = .popUpMenu
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        isOpaque = false
        backgroundColor = .clear
        hasShadow = true
        animationBehavior = .utilityWindow
        isReleasedWhenClosed = false

        let background = NSVisualEffectView()
        background.material = .menu
        background.blendingMode = .behindWindow
        background.state = .active
        // The material renders in its own backdrop layer, which ignores
        // `layer.cornerRadius` and leaves square corners behind; a mask
        // image is what actually clips it.
        background.maskImage = Self.roundedMask(radius: FlyoutStyle.cornerRadius)

        let hosting = NSHostingView(rootView: rootView.onGeometryChange(for: CGSize.self) { $0.size } action: { [weak self] size in
            self?.resize(to: size)
        })
        hosting.translatesAutoresizingMaskIntoConstraints = false
        background.addSubview(hosting)
        NSLayoutConstraint.activate([
            hosting.leadingAnchor.constraint(equalTo: background.leadingAnchor),
            hosting.trailingAnchor.constraint(equalTo: background.trailingAnchor),
            hosting.topAnchor.constraint(equalTo: background.topAnchor),
            hosting.bottomAnchor.constraint(equalTo: background.bottomAnchor),
        ])
        contentView = background
        resize(to: hosting.fittingSize)
    }

    /// Stretchable rounded rectangle: only the corners keep their shape.
    private static func roundedMask(radius: CGFloat) -> NSImage {
        let edge = 2 * radius + 1
        let image = NSImage(size: NSSize(width: edge, height: edge), flipped: false) { rect in
            NSColor.black.setFill()
            NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius).fill()
            return true
        }
        image.capInsets = NSEdgeInsets(top: radius, left: radius, bottom: radius, right: radius)
        image.resizingMode = .stretch
        return image
    }

    // Lets Escape and the buttons work without activating the app.
    override var canBecomeKey: Bool { true }

    override func makeKeyAndOrderFront(_ sender: Any?) {
        super.makeKeyAndOrderFront(sender)
        // Becoming key would otherwise focus the first button.
        makeFirstResponder(nil)
    }

    override func cancelOperation(_ sender: Any?) {
        close()
    }

    override func resignKey() {
        super.resignKey()
        close()
    }

    override func close() {
        super.close()
        onClose?()
    }

    private func resize(to size: CGSize) {
        guard size.width > 0, size.height > 0, size != frame.size else { return }
        let top = frame.maxY
        setFrame(NSRect(x: frame.minX, y: top - size.height, width: size.width, height: size.height), display: true)
        // The shadow follows the rounded content only once recomputed.
        invalidateShadow()
        onSizeChange?()
    }
}
