import SwiftUI

/// Plain-English event log (Track 4B).
/// Reads audit events from the Sanctuary server's HTTP API.
/// Never reads encrypted files from ~/.sanctuary/ directly.
struct ActivityLogView: View {
    @ObservedObject var serverBridge: SanctuaryServerBridge
    @State private var events: [AuditEvent] = []
    @State private var isLoading = false
    @State private var pollTimer: Timer?

    var body: some View {
        VStack(spacing: 0) {
            if serverBridge.serverStatus == .unreachable {
                serverOfflineView
            } else if isLoading && events.isEmpty {
                Spacer()
                ProgressView("Loading activity...")
                Spacer()
            } else if events.isEmpty {
                Spacer()
                Text("No activity yet")
                    .font(.headline)
                    .foregroundColor(.secondary)
                Text("Events will appear here as your agents are protected and used.")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 4)
                Spacer()
            } else {
                eventList
            }
        }
        .task {
            await loadEvents()
            startPolling()
        }
        .onDisappear {
            stopPolling()
        }
    }

    // MARK: - Server offline

    private var serverOfflineView: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "wifi.slash")
                .font(.largeTitle)
                .foregroundColor(.secondary)
            Text("Waiting for Sanctuary server...")
                .font(.headline)
                .foregroundColor(.secondary)
            if serverBridge.sanctuaryPath != nil {
                Button("Start Server") {
                    Task {
                        _ = await serverBridge.startServer()
                        try? await Task.sleep(nanoseconds: 2_000_000_000)
                        await serverBridge.checkServerHealth()
                        await loadEvents()
                    }
                }
            }
            Spacer()
        }
    }

    // MARK: - Event list

    private var eventList: some View {
        ScrollView {
            LazyVStack(spacing: 1) {
                ForEach(events) { event in
                    eventRow(event)
                }
            }
            .padding(.vertical, 8)
        }
    }

    private func eventRow(_ event: AuditEvent) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Circle()
                .fill(colorForEvent(event))
                .frame(width: 8, height: 8)
                .padding(.top, 6)

            VStack(alignment: .leading, spacing: 2) {
                Text(event.plainEnglish)
                    .font(.body)
                Text(formatTimestamp(event.timestamp))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private func colorForEvent(_ event: AuditEvent) -> Color {
        switch event.color {
        case .red: return .red
        case .green: return .green
        case .yellow: return .yellow
        default: return .gray
        }
    }

    private func formatTimestamp(_ ts: String) -> String {
        // ISO 8601 to relative time
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: ts) else {
            // Try without fractional seconds
            formatter.formatOptions = [.withInternetDateTime]
            guard let date = formatter.date(from: ts) else {
                return ts
            }
            return RelativeDateTimeFormatter().localizedString(for: date, relativeTo: Date())
        }
        return RelativeDateTimeFormatter().localizedString(for: date, relativeTo: Date())
    }

    // MARK: - Polling

    private func loadEvents() async {
        isLoading = true
        defer { isLoading = false }
        events = await serverBridge.fetchAuditLog()
    }

    private func startPolling() {
        pollTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { _ in
            Task { @MainActor in
                events = await serverBridge.fetchAuditLog()
            }
        }
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }
}
