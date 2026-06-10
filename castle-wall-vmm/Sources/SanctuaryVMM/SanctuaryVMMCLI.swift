import Foundation

/// CLI for the Sanctuary VMM (Apple Containerization substrate).
///
/// Commands:
///   guest-exec --json <request>   Execute a process inside a no-network VM
///   hash       --path <file>      Compute SHA-256 of a file (for pin generation)
///
/// The binary is spawned by the host-side vm-launcher.ts adapter.
/// It is NOT a long-running daemon; it boots a VM, runs the command, and exits.
public enum SanctuaryVMMCLI {

    public static func run(arguments: [String] = CommandLine.arguments) async throws -> Int32 {
        let args = Array(arguments.dropFirst())

        guard let command = args.first else {
            printUsage()
            return 1
        }

        switch command {
        case "guest-exec":
            return try await handleGuestExec(args: Array(args.dropFirst()))
        case "run-box":
            return try await handleRunBox(args: Array(args.dropFirst()))
        case "hash":
            return try handleHash(args: Array(args.dropFirst()))
        default:
            fputs("Unknown command: \(command)\n", stderr)
            printUsage()
            return 1
        }
    }

    private static func printUsage() {
        fputs("""
        Usage: sanctuary-vmm <command> [options]

        Commands:
          guest-exec --json <request>   Execute a process in a no-network VM (no egress)
          run-box    --json <request>   Boot a no-network VM with egress bridge wired
          hash       --path <file>      Compute SHA-256 of a file

        \n
        """, stderr)
    }

    // MARK: - guest-exec

    private static func handleGuestExec(args: [String]) async throws -> Int32 {
        guard let jsonIdx = args.firstIndex(of: "--json"),
              jsonIdx + 1 < args.count else {
            fputs("guest-exec requires --json <request>\n", stderr)
            return 1
        }

        let jsonString = args[jsonIdx + 1]
        guard let jsonData = jsonString.data(using: .utf8) else {
            fputs("Invalid JSON encoding\n", stderr)
            return 1
        }

        let request: GuestExecCLIRequest
        do {
            request = try JSONDecoder().decode(GuestExecCLIRequest.self, from: jsonData)
        } catch {
            fputs("Failed to parse request JSON: \(error)\n", stderr)
            return 1
        }

        let config = SanctuaryContainerConfig(
            kernelPath: request.kernelPath,
            initfsReference: request.initfsReference ?? "ghcr.io/apple/containerization/vminit:0.33.3",
            ociImageReference: request.ociImageReference,
            rootfsSizeBytes: request.rootfsSizeBytes ?? 2 * 1024 * 1024 * 1024,
            cpuCount: request.cpuCount ?? 2,
            memoryBytes: request.memoryBytes ?? 512 * 1024 * 1024,
            rootfsPins: request.rootfsPins ?? [],
            egressVsockPort: request.egressVsockPort ?? 0x0FFF_0001,
            applyGuestJail: request.applyGuestJail ?? true
        )

        let launcher = SanctuaryContainerLauncher(config: config)
        let containerId = "sanctuary-\(ProcessInfo.processInfo.processIdentifier)"

        let execRequest = SanctuaryGuestExecRequest(
            command: request.command,
            args: request.args,
            cwd: request.cwd,
            env: request.env
        )

        let result = try await launcher.launchAndExec(
            containerId: containerId,
            request: execRequest
        )

        // Output result as JSON
        let output = GuestExecCLIOutput(
            exitCode: result.exitCode,
            stdout: result.stdout,
            stderr: result.stderr
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let outputData = try encoder.encode(output)
        print(String(data: outputData, encoding: .utf8) ?? "{}")

        return result.exitCode
    }

    // MARK: - run-box

    private static func handleRunBox(args: [String]) async throws -> Int32 {
        guard let jsonIdx = args.firstIndex(of: "--json"),
              jsonIdx + 1 < args.count else {
            fputs("run-box requires --json <request>\n", stderr)
            return 1
        }

        let jsonString = args[jsonIdx + 1]
        guard let jsonData = jsonString.data(using: .utf8) else {
            fputs("Invalid JSON encoding\n", stderr)
            return 1
        }

        let request: RunBoxCLIRequest
        do {
            request = try JSONDecoder().decode(RunBoxCLIRequest.self, from: jsonData)
        } catch {
            fputs("Failed to parse run-box request JSON: \(error)\n", stderr)
            return 1
        }

        guard !request.egressProxyUdsPath.isEmpty else {
            fputs("run-box requires egressProxyUdsPath\n", stderr)
            return 1
        }

        let containerConfig = SanctuaryContainerConfig(
            kernelPath: request.kernelPath,
            initfsReference: request.initfsReference ?? "ghcr.io/apple/containerization/vminit:0.33.3",
            ociImageReference: request.ociImageReference,
            rootfsSizeBytes: request.rootfsSizeBytes ?? 2 * 1024 * 1024 * 1024,
            cpuCount: request.cpuCount ?? 2,
            memoryBytes: request.memoryBytes ?? 512 * 1024 * 1024,
            rootfsPins: request.rootfsPins ?? [],
            egressVsockPort: request.egressVsockPort ?? 0x0FFF_0001,
            applyGuestJail: request.applyGuestJail ?? true
        )

        let egressConfig = SanctuaryVsockEgressConfig(
            hostProxyUdsPath: request.egressProxyUdsPath,
            guestSocketPath: request.egressGuestSocketPath ?? "/run/sanctuary-egress.sock"
        )

        let launcher = SanctuaryContainerLauncher(config: containerConfig)
        let containerId = "sanctuary-\(ProcessInfo.processInfo.processIdentifier)"

        let execRequest = SanctuaryGuestExecRequest(
            command: request.command,
            args: request.args,
            cwd: request.cwd,
            env: request.env
        )

        fputs("[run-box] booting with egress: guest \(egressConfig.guestSocketPath) -> host UDS \(egressConfig.hostProxyUdsPath)\n", stderr)

        let result = try await launcher.launchWithEgress(
            containerId: containerId,
            request: execRequest,
            egressConfig: egressConfig
        )

        // Output result as JSON
        let output = GuestExecCLIOutput(
            exitCode: result.exitCode,
            stdout: result.stdout,
            stderr: result.stderr
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let outputData = try encoder.encode(output)
        print(String(data: outputData, encoding: .utf8) ?? "{}")

        return result.exitCode
    }

    // MARK: - hash

    private static func handleHash(args: [String]) throws -> Int32 {
        guard let pathIdx = args.firstIndex(of: "--path"),
              pathIdx + 1 < args.count else {
            fputs("hash requires --path <file>\n", stderr)
            return 1
        }

        let path = args[pathIdx + 1]
        let url = URL(fileURLWithPath: path)
        let digest = try SanctuaryImageIntegrity.computeDigest(at: url)
        print(digest)
        return 0
    }
}

// MARK: - CLI data types

struct GuestExecCLIRequest: Codable {
    let kernelPath: String
    let initfsReference: String?
    let ociImageReference: String
    let rootfsSizeBytes: UInt64?
    let cpuCount: Int?
    let memoryBytes: UInt64?
    let rootfsPins: [SanctuaryArtifactPin]?
    let egressVsockPort: UInt32?
    let applyGuestJail: Bool?
    let command: String
    let args: [String]
    let cwd: String
    let env: [String: String]
}

struct RunBoxCLIRequest: Codable {
    let kernelPath: String
    let initfsReference: String?
    let ociImageReference: String
    let rootfsSizeBytes: UInt64?
    let cpuCount: Int?
    let memoryBytes: UInt64?
    let rootfsPins: [SanctuaryArtifactPin]?
    let egressVsockPort: UInt32?
    let applyGuestJail: Bool?
    let egressProxyUdsPath: String
    let egressGuestSocketPath: String?
    let command: String
    let args: [String]
    let cwd: String
    let env: [String: String]
}

struct GuestExecCLIOutput: Codable {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}
