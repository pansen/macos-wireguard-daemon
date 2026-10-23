import Foundation
import Observation

/// Polls the Rust core and publishes its snapshot to the UI.
@MainActor
@Observable
final class StatusModel {
    private(set) var snapshot: Snapshot?
    private(set) var updatedAt: Date?

    /// Matches the helper's 3 s reconcile tick closely enough without
    /// keeping the daemon busy.
    private let interval: Duration = .seconds(5)

    var overall: Overall { snapshot?.overall ?? .unavailable }

    init() {
        // The model lives as long as the app, so the loop never ends.
        Task {
            while true {
                await refresh()
                try? await Task.sleep(for: interval)
            }
        }
    }

    func refresh() async {
        // `snapshot()` blocks on the daemon socket.
        let next = await Task.detached(priority: .utility) { WgdBar.snapshot() }.value
        snapshot = next
        updatedAt = Date()
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
