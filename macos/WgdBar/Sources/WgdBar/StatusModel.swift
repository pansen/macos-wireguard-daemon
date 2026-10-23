import Foundation
import Observation
import notify

/// Fetches the snapshot from the Rust core when the daemon or a helper posts
/// the status notification, and on a slow fallback timer.
@MainActor
@Observable
final class StatusModel {
    private(set) var snapshot: Snapshot?
    private(set) var updatedAt: Date?

    /// Covers lost notifications and a daemon that is not running at all
    /// (then nobody posts).
    private let fallbackInterval: Duration = .seconds(30)
    /// Daemon and helper can post several times for one change (disconnect,
    /// then the helper's exit); fetch once.
    private let debounce: Duration = .milliseconds(250)

    private var pendingRefresh: Task<Void, Never>?
    /// Concurrent fetches may finish out of order; only the newest counts.
    private var latestRequest = 0

    var overall: Overall { snapshot?.overall ?? .unavailable }

    init() {
        subscribe()
        // The model lives as long as the app, so the loop never ends.
        Task {
            while true {
                await refresh()
                try? await Task.sleep(for: fallbackInterval)
            }
        }
    }

    func refresh() async {
        latestRequest += 1
        let request = latestRequest
        // `snapshot()` blocks on the daemon socket.
        let next = await Task.detached(priority: .utility) { WgdBar.snapshot() }.value
        guard request == latestRequest else { return }
        snapshot = next
        updatedAt = Date()
    }

    private func subscribe() {
        var token: Int32 = 0
        let status = notify_register_dispatch(statusNotificationName(), &token, .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.scheduleRefresh() }
        }
        // Without the subscription the fallback timer still keeps the icon
        // roughly current.
        if status != NOTIFY_STATUS_OK {
            NSLog("WgdBar: notify_register_dispatch failed with status %d", status)
        }
    }

    private func scheduleRefresh() {
        pendingRefresh?.cancel()
        pendingRefresh = Task {
            try? await Task.sleep(for: debounce)
            guard !Task.isCancelled else { return }
            await refresh()
        }
    }
}

extension Overall {
    var symbol: String {
        switch self {
        case .active: "lock.shield.fill"
        case .pulledBack: "exclamationmark.shield"
        case .inactive: "shield"
        case .disconnected, .noConnections: "shield.slash"
        case .unavailable: "xmark.shield"
        }
    }

    var title: String {
        switch self {
        case .active: "Reconciler active"
        case .pulledBack: "Tunnel DNS pulled back"
        case .inactive: "Connected, DNS not in effect"
        case .disconnected: "Disconnected"
        case .noConnections: "No connections"
        case .unavailable: "wgd unavailable"
        }
    }
}
