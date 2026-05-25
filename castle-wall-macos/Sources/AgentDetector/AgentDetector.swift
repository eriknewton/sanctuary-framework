import Foundation
#if canImport(AppKit)
import AppKit
#endif

/// Detects installed and running AI agents on the local machine.
///
/// Detection strategy:
/// 1. File scanner: checks known install locations for agent binaries
/// 2. Process scanner: checks running processes against known names
/// 3. Signature scanner: checks for agent-specific config/markers
///
/// The host app is NOT sandboxed, so filesystem and process scanning
/// work without additional entitlements.
public final class AgentDetector: ObservableObject {
    @Published public private(set) var agents: [AgentRecord] = []
    @Published public private(set) var isScanning: Bool = false

    public init() {}

    /// Run a full detection scan. Updates `agents` on the main thread.
    @MainActor
    public func scan() async {
        isScanning = true
        defer { isScanning = false }

        let runningProcesses = Self.runningProcessNames()
        var found: [AgentRecord] = []

        for definition in Self.knownAgents {
            if let record = detect(definition: definition, runningProcesses: runningProcesses) {
                found.append(record)
            }
        }

        agents = found
    }

    // MARK: - Known agent definitions

    private struct AgentDefinition {
        let id: String
        let name: String
        let harnessFlag: String
        let binaryPaths: [String]
        let processNames: [String]
        let signatureMarkers: [String]
        let signatureGlob: String?
        let bundleIdentifier: String?

        init(
            id: String, name: String, harnessFlag: String,
            binaryPaths: [String], processNames: [String],
            signatureMarkers: [String], signatureGlob: String? = nil,
            bundleIdentifier: String? = nil
        ) {
            self.id = id; self.name = name; self.harnessFlag = harnessFlag
            self.binaryPaths = binaryPaths; self.processNames = processNames
            self.signatureMarkers = signatureMarkers; self.signatureGlob = signatureGlob
            self.bundleIdentifier = bundleIdentifier
        }
    }

    private static let knownAgents: [AgentDefinition] = {
        let home = NSHomeDirectory()
        return [
            AgentDefinition(
                id: "openclaw",
                name: "OpenClaw",
                harnessFlag: "--openclaw",
                binaryPaths: [
                    "/Applications/OpenClaw.app",
                    "\(home)/Applications/OpenClaw.app",
                    "/usr/local/bin/openclaw",
                    "/opt/homebrew/bin/openclaw",
                ],
                processNames: ["openclaw", "OpenClaw"],
                signatureMarkers: [
                    "\(home)/.openclaw",
                ],
                bundleIdentifier: nil
            ),
            AgentDefinition(
                id: "claude-desktop",
                name: "Claude Desktop",
                harnessFlag: "--claude-code",
                binaryPaths: [
                    "/Applications/Claude.app",
                ],
                processNames: ["Claude"],
                signatureMarkers: [],
                bundleIdentifier: "com.anthropic.claude"
            ),
            AgentDefinition(
                id: "claude-code",
                name: "Claude Code",
                harnessFlag: "--claude-code",
                binaryPaths: [
                    "/usr/local/bin/claude",
                    "/opt/homebrew/bin/claude",
                    "\(home)/.npm-global/bin/claude",
                ],
                processNames: ["claude"],
                signatureMarkers: [],
                bundleIdentifier: nil
            ),
            AgentDefinition(
                id: "codex",
                name: "Codex CLI",
                harnessFlag: "--wrap",
                binaryPaths: [
                    "/usr/local/bin/codex",
                    "/opt/homebrew/bin/codex",
                    "\(home)/.npm-global/bin/codex",
                ],
                processNames: ["codex"],
                signatureMarkers: [],
                bundleIdentifier: nil
            ),
            AgentDefinition(
                id: "hermes",
                name: "Hermes",
                harnessFlag: "--hermes",
                binaryPaths: [
                    "/Applications/Hermes.app",
                    "\(home)/Applications/Hermes.app",
                    "/usr/local/bin/hermes",
                    "/opt/homebrew/bin/hermes",
                ],
                processNames: ["hermes", "Hermes"],
                signatureMarkers: [],
                bundleIdentifier: nil
            ),
            AgentDefinition(
                id: "cursor",
                name: "Cursor",
                harnessFlag: "--cursor",
                binaryPaths: [
                    "/Applications/Cursor.app",
                ],
                processNames: ["Cursor"],
                signatureMarkers: [],
                bundleIdentifier: nil
            ),
            AgentDefinition(
                id: "cline",
                name: "Cline",
                harnessFlag: "--cline",
                binaryPaths: [],
                processNames: ["cline"],
                signatureMarkers: [],
                signatureGlob: "\(home)/.vscode/extensions/saoudrizwan.claude-dev-*",
                bundleIdentifier: nil
            ),
        ]
    }()

    // MARK: - Detection

    private func detect(
        definition: AgentDefinition,
        runningProcesses: Set<String>
    ) -> AgentRecord? {
        let fm = FileManager.default

        // Check binary paths
        var foundPath: String?
        for path in definition.binaryPaths {
            if fm.fileExists(atPath: path) {
                foundPath = path
                break
            }
        }

        // Check signature markers (exact paths)
        var hasSignature = false
        for marker in definition.signatureMarkers {
            if fm.fileExists(atPath: marker) {
                hasSignature = true
                break
            }
        }

        // Check signature glob (e.g. VS Code extension pattern)
        if !hasSignature, let glob = definition.signatureGlob {
            hasSignature = Self.globMatchExists(pattern: glob)
        }

        // Check bundle identifier (macOS apps)
        var hasBundleMatch = false
        if let bundleId = definition.bundleIdentifier {
            hasBundleMatch = Self.appExists(bundleIdentifier: bundleId)
        }

        // Check running processes
        let isRunning = definition.processNames.contains { name in
            runningProcesses.contains(name)
        }

        // Must have at least one signal to report
        guard foundPath != nil || hasSignature || hasBundleMatch || isRunning else {
            return nil
        }

        // Try to get version from app bundle
        var version: String?
        if let path = foundPath, path.hasSuffix(".app") {
            version = Self.appVersion(at: path)
        }

        return AgentRecord(
            id: definition.id,
            name: definition.name,
            binaryPath: foundPath,
            version: version,
            isRunning: isRunning,
            harnessFlag: definition.harnessFlag,
            suggestedProtectDefault: isRunning
        )
    }

    // MARK: - Process scanning

    private static func runningProcessNames() -> Set<String> {
        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axco", "command"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return []
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return [] }

        var names = Set<String>()
        for line in output.split(separator: "\n") {
            let name = line.trimmingCharacters(in: .whitespaces)
            if !name.isEmpty && name != "COMMAND" {
                names.insert(name)
            }
        }
        return names
    }

    // MARK: - App bundle helpers

    private static func appExists(bundleIdentifier: String) -> Bool {
        if #available(macOS 12.0, *) {
            return NSWorkspace.shared.urlForApplication(
                withBundleIdentifier: bundleIdentifier
            ) != nil
        }
        return false
    }

    private static func appVersion(at path: String) -> String? {
        guard let bundle = Bundle(path: path) else { return nil }
        return bundle.infoDictionary?["CFBundleShortVersionString"] as? String
    }

    /// Check if any file matches a simple glob pattern (supports trailing `*` only).
    private static func globMatchExists(pattern: String) -> Bool {
        guard let starIndex = pattern.lastIndex(of: "*") else {
            return FileManager.default.fileExists(atPath: pattern)
        }
        let dir = String(pattern[pattern.startIndex..<pattern.lastIndex(of: "/")!])
        let prefix = String(pattern[pattern.index(after: pattern.lastIndex(of: "/")!)..<starIndex])
        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: dir) else {
            return false
        }
        return contents.contains { $0.hasPrefix(prefix) }
    }
}
