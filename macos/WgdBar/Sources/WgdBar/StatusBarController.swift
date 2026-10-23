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

        let background = FlyoutBackgroundView()

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

/// Opaque, nearly white like the system menus and Stats (`#FAFAFA` in light
/// mode). The `.menu` material came out a noticeably darker grey. A plain
/// layer also rounds cleanly with `cornerRadius`, unlike a visual effect
/// view's backdrop.
private final class FlyoutBackgroundView: NSView {
    private static let fill = NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            ? NSColor(white: 0.16, alpha: 1)
            : NSColor(white: 0.98, alpha: 1)
    }
    private static let border = NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            ? NSColor(white: 1, alpha: 0.12)
            : NSColor(white: 0, alpha: 0.12)
    }

    override init(frame: NSRect) {
        super.init(frame: frame)
        wantsLayer = true
        layer?.cornerRadius = FlyoutStyle.cornerRadius
        layer?.cornerCurve = .continuous
        layer?.masksToBounds = true
        layer?.borderWidth = 0.5
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    override var wantsUpdateLayer: Bool { true }

    // Called again on every light/dark switch; CGColors don't follow the
    // appearance by themselves.
    override func updateLayer() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            layer?.backgroundColor = Self.fill.cgColor
            layer?.borderColor = Self.border.cgColor
        }
    }
}
