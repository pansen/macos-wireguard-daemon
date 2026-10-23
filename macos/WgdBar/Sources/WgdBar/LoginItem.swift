import Observation
import ServiceManagement

/// "Open at login" through `SMAppService`. Off until the user turns it on:
/// nothing registers the app on its own.
@MainActor
@Observable
final class LoginItem {
    private(set) var status = SMAppService.mainApp.status
    private(set) var error: String?

    /// Registered, though macOS may still wait for approval in System
    /// Settings (`needsApproval`).
    var isOn: Bool { status == .enabled || status == .requiresApproval }
    var needsApproval: Bool { status == .requiresApproval }

    func set(_ on: Bool) {
        do {
            if on {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        refresh()
    }

    /// The user can change it in System Settings at any time; called each
    /// time the flyout opens.
    func refresh() {
        status = SMAppService.mainApp.status
    }

    func openSystemSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }
}
