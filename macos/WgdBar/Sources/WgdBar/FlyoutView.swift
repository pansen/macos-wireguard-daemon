import SwiftUI

enum FlyoutStyle {
    /// Shared by the panel and the rows inside it.
    static let cornerRadius: CGFloat = 6
}

struct FlyoutView: View {
    let model: StatusModel
    let loginItem: LoginItem

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                header
                if let error = model.snapshot?.error {
                    Text(error)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                ForEach(model.snapshot?.connections ?? [], id: \.interface) { line in
                    ConnectionRow(line: line)
                }
            }
            .padding(14)
            // Edge to edge, outside the content padding.
            Divider()
            footer
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
        }
        .frame(width: 320)
        .animation(.spring(response: 0.3, dampingFraction: 0.88), value: model.snapshot)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: model.overall.symbol)
                .font(.title2)
                .foregroundStyle(model.overall.tint)
                .contentTransition(.symbolEffect(.replace))
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.overall.title).font(.headline)
                if let updatedAt = model.updatedAt {
                    Text("Updated \(updatedAt, style: .relative) ago")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Button("Refresh") { Task { await model.refresh() } }
                Spacer()
                Toggle(isOn: Binding(get: { loginItem.isOn }, set: { loginItem.set($0) })) {
                    Text("Open at login")
                }
                .toggleStyle(.switch)
                .controlSize(.mini)
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }
            }
            .buttonStyle(.borderless)
            // Borderless buttons draw secondary in a non-key app, the toggle
            // label primary; one explicit style keeps the row uniform.
            .foregroundStyle(.secondary)
            if loginItem.needsApproval {
                Button("Open at login needs approval in System Settings") {
                    loginItem.openSystemSettings()
                }
                .buttonStyle(.link)
                .font(.caption)
            }
            if let error = loginItem.error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        // Out of the key view loop, so opening the panel with keyboard
        // navigation enabled doesn't put a focus ring on "Refresh".
        .focusable(false)
        .font(.callout)
    }
}

private struct ConnectionRow: View {
    let line: ConnectionLine

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Circle()
                .fill(line.state.tint)
                .frame(width: 8, height: 8)
                .padding(.top, 5)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(line.title).font(.body.weight(.medium))
                    if line.global {
                        Text("global")
                            .font(.caption2)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(.quaternary, in: Capsule())
                    }
                    Spacer()
                    Text(line.interface)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
                Text(line.detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(10)
        .background(rowBackground)
    }

    @ViewBuilder
    private var rowBackground: some View {
        let shape = RoundedRectangle(cornerRadius: FlyoutStyle.cornerRadius, style: .continuous)
        if #available(macOS 26, *) {
            shape.fill(.clear).glassEffect(.regular.tint(line.state.tint.opacity(0.15)), in: shape)
        } else {
            shape.fill(.ultraThinMaterial)
        }
    }
}

extension Overall {
    var tint: Color {
        switch self {
        case .active: .green
        case .pulledBack: .orange
        case .inactive: .yellow
        case .disconnected, .noConnections: .secondary
        case .unavailable: .red
        }
    }
}
