import XCTest
@testable import SanctuaryVMM

final class SanctuaryContainerLauncherTests: XCTestCase {

    // MARK: - Config defaults

    func testDefaultConfig() {
        let config = SanctuaryContainerConfig(
            kernelPath: "/path/to/vmlinux",
            ociImageReference: "docker.io/library/alpine:3.21"
        )
        XCTAssertEqual(config.kernelPath, "/path/to/vmlinux")
        XCTAssertEqual(config.initfsReference, "ghcr.io/apple/containerization/vminit:0.33.3")
        XCTAssertEqual(config.ociImageReference, "docker.io/library/alpine:3.21")
        XCTAssertEqual(config.rootfsSizeBytes, 2 * 1024 * 1024 * 1024)
        XCTAssertEqual(config.cpuCount, 2)
        XCTAssertEqual(config.memoryBytes, 512 * 1024 * 1024)
        XCTAssertTrue(config.rootfsPins.isEmpty)
        // Egress port is below Apple's 0x1000_0000 range to avoid collision
        XCTAssertEqual(config.egressVsockPort, 0x0FFF_0001)
        XCTAssertTrue(config.egressVsockPort < 0x1000_0000,
            "Egress port must be below LinuxPod's hostVsockPorts range (0x1000_0000+)")
    }

    func testCustomConfig() {
        let pins = [SanctuaryArtifactPin(sha256: "abc123", artifact: "rootfs.ext4")]
        let config = SanctuaryContainerConfig(
            kernelPath: "/custom/kernel",
            initfsReference: "custom-initfs:1.0",
            ociImageReference: "custom/image:latest",
            rootfsSizeBytes: 4 * 1024 * 1024 * 1024,
            cpuCount: 4,
            memoryBytes: 1024 * 1024 * 1024,
            rootfsPins: pins,
            egressVsockPort: 0x0FFF_0002
        )
        XCTAssertEqual(config.cpuCount, 4)
        XCTAssertEqual(config.memoryBytes, 1024 * 1024 * 1024)
        XCTAssertEqual(config.rootfsPins.count, 1)
        XCTAssertEqual(config.egressVsockPort, 0x0FFF_0002)
    }

    // MARK: - GuestExecRequest

    func testGuestExecRequestCodable() throws {
        let request = SanctuaryGuestExecRequest(
            command: "/usr/local/bin/node",
            args: ["--version"],
            cwd: "/workspace",
            env: ["PATH": "/usr/local/bin:/usr/bin", "HOME": "/root"]
        )
        let data = try JSONEncoder().encode(request)
        let decoded = try JSONDecoder().decode(SanctuaryGuestExecRequest.self, from: data)
        XCTAssertEqual(decoded.command, request.command)
        XCTAssertEqual(decoded.args, request.args)
        XCTAssertEqual(decoded.cwd, request.cwd)
        XCTAssertEqual(decoded.env, request.env)
    }

    // MARK: - GuestExecResult

    func testGuestExecResult() {
        let result = SanctuaryGuestExecResult(
            exitCode: 0,
            stdout: "v22.0.0\n",
            stderr: ""
        )
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(result.stdout, "v22.0.0\n")
        XCTAssertTrue(result.stderr.isEmpty)
    }

    // MARK: - Port model invariant

    func testEgressPortDoesNotCollideWithAppleRange() {
        // LinuxPod.swift:238-239 — both hostVsockPorts and guestVsockPorts
        // start at 0x1000_0000 and increment upward.
        // Our egress port must be BELOW this range.
        let applePortRangeStart: UInt32 = 0x1000_0000
        let defaultEgressPort = SanctuaryContainerConfig(
            kernelPath: "", ociImageReference: ""
        ).egressVsockPort

        XCTAssertTrue(defaultEgressPort < applePortRangeStart,
            "Default egress port \(String(format: "0x%08X", defaultEgressPort)) must be below " +
            "Apple's port range starting at \(String(format: "0x%08X", applePortRangeStart))")

        // Also verify it's not port 1024 (vminitd control)
        XCTAssertNotEqual(defaultEgressPort, 1024,
            "Egress port must not be vminitd control port 1024")
    }
}
