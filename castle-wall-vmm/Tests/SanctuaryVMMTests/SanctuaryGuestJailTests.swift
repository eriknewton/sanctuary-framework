import XCTest
@testable import SanctuaryVMM

final class SanctuaryGuestJailTests: XCTestCase {

    // MARK: - ELF fixture builder

    /// Build a minimal ELF64 image: 64-byte header + program header table.
    /// `machine` is e_machine (0xB7 = aarch64, 0x3E = x86_64); `phTypes` are
    /// the p_type values of consecutive program headers (PT_LOAD = 1,
    /// PT_INTERP = 3).
    private func makeELF(machine: UInt16, phTypes: [UInt32]) -> Data {
        let phentsize = 56
        var data = Data(count: 64 + phTypes.count * phentsize)
        data[0] = 0x7F; data[1] = 0x45; data[2] = 0x4C; data[3] = 0x46  // \x7fELF
        data[4] = 2  // ELFCLASS64
        data[5] = 1  // ELFDATA2LSB
        data[6] = 1  // EV_CURRENT
        data[18] = UInt8(machine & 0xFF)
        data[19] = UInt8(machine >> 8)
        // e_phoff = 64 (u64 LE at offset 32)
        data[32] = 64
        // e_phentsize (u16 at 54), e_phnum (u16 at 56)
        data[54] = UInt8(phentsize)
        data[56] = UInt8(phTypes.count)
        for (i, pType) in phTypes.enumerated() {
            let base = 64 + i * phentsize
            data[base] = UInt8(pType & 0xFF)
            data[base + 1] = UInt8((pType >> 8) & 0xFF)
            data[base + 2] = UInt8((pType >> 16) & 0xFF)
            data[base + 3] = UInt8((pType >> 24) & 0xFF)
        }
        return data
    }

    private func writeTempFile(_ data: Data, name: String = "shim-under-test") throws -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("guest-jail-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent(name)
        try data.write(to: file)
        return file.path
    }

    // MARK: - argv wrapping

    func testPythonWrapShape() {
        let argv = SanctuaryGuestJail.wrap(command: "/plugin/run", args: ["--flag", "x"])
        XCTAssertEqual(argv.first, "python3")
        XCTAssertEqual(argv[1], "-c")
        XCTAssertTrue(argv.contains("--"), "argv must carry the -- sentinel")
        XCTAssertEqual(Array(argv.suffix(3)), ["/plugin/run", "--flag", "x"])
    }

    func testStaticBinaryWrapShape() {
        let argv = SanctuaryGuestJail.wrapWithStaticBinary(command: "/plugin/run", args: ["--flag"])
        XCTAssertEqual(argv, ["/run/sanctuary-jail/sanctuary-jail", "--", "/plugin/run", "--flag"])
    }

    // MARK: - delivery parsing (fail-closed)

    func testParseDeliveryDefaultsToPythonPreamble() throws {
        XCTAssertEqual(
            try SanctuaryGuestJail.parseDelivery(mode: nil, staticBinaryPath: nil),
            .pythonPreamble
        )
        XCTAssertEqual(
            try SanctuaryGuestJail.parseDelivery(mode: "python-preamble", staticBinaryPath: nil),
            .pythonPreamble
        )
    }

    func testParseDeliveryStaticBinary() throws {
        XCTAssertEqual(
            try SanctuaryGuestJail.parseDelivery(mode: "static-binary", staticBinaryPath: "/x/jail"),
            .staticBinary(hostBinaryPath: "/x/jail")
        )
    }

    func testParseDeliveryStaticBinaryWithoutPathFailsClosed() {
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(mode: "static-binary", staticBinaryPath: nil)
        )
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(mode: "static-binary", staticBinaryPath: "")
        )
    }

    func testParseDeliveryUnknownModeFailsClosed() {
        // An unknown mode must never silently fall back to python delivery.
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(mode: "none", staticBinaryPath: nil)
        )
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(mode: "Static-Binary", staticBinaryPath: "/x/jail")
        )
    }

    func testParseDeliveryPathWithPythonModeFailsClosed() {
        // Ambiguous intent (a static path but python mode) is rejected rather
        // than guessed.
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(mode: nil, staticBinaryPath: "/x/jail")
        )
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(mode: "python-preamble", staticBinaryPath: "/x/jail")
        )
    }

    // MARK: - static shim validation (fail-closed)

    func testValidateAcceptsStaticAarch64ELF() throws {
        let path = try writeTempFile(makeELF(machine: 0xB7, phTypes: [1, 1]))
        XCTAssertNoThrow(try SanctuaryGuestJail.validateStaticShim(atPath: path))
    }

    func testValidateRejectsMissingFile() {
        XCTAssertThrowsError(
            try SanctuaryGuestJail.validateStaticShim(atPath: "/nonexistent/sanctuary-jail")
        ) { error in
            guard case SanctuaryGuestJailError.staticBinaryMissing = error else {
                return XCTFail("expected staticBinaryMissing, got \(error)")
            }
        }
    }

    func testValidateRejectsDirectory() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("guest-jail-dir-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        XCTAssertThrowsError(try SanctuaryGuestJail.validateStaticShim(atPath: dir.path))
    }

    func testValidateRejectsEmptyFile() throws {
        let path = try writeTempFile(Data())
        XCTAssertThrowsError(try SanctuaryGuestJail.validateStaticShim(atPath: path))
    }

    func testValidateRejectsNonELF() throws {
        let path = try writeTempFile(Data("#!/bin/sh\necho not-a-jail\n".utf8))
        XCTAssertThrowsError(try SanctuaryGuestJail.validateStaticShim(atPath: path))
    }

    func testValidateRejectsWrongMachine() throws {
        // x86_64 shim cannot run in the .linuxArm guest; must be rejected
        // host-side rather than exec-failing confusingly in-guest.
        let path = try writeTempFile(makeELF(machine: 0x3E, phTypes: [1]))
        XCTAssertThrowsError(try SanctuaryGuestJail.validateStaticShim(atPath: path)) { error in
            guard case SanctuaryGuestJailError.staticBinaryInvalid(_, let reason) = error else {
                return XCTFail("expected staticBinaryInvalid, got \(error)")
            }
            XCTAssertTrue(reason.contains("aarch64"), "reason should name the required arch: \(reason)")
        }
    }

    func testValidateRejectsDynamicallyLinkedELF() throws {
        // PT_INTERP (3) marks a dynamically linked binary — would fail on
        // libc-less guest images, so it is rejected up front.
        let path = try writeTempFile(makeELF(machine: 0xB7, phTypes: [3, 1]))
        XCTAssertThrowsError(try SanctuaryGuestJail.validateStaticShim(atPath: path)) { error in
            guard case SanctuaryGuestJailError.staticBinaryInvalid(_, let reason) = error else {
                return XCTFail("expected staticBinaryInvalid, got \(error)")
            }
            XCTAssertTrue(reason.contains("dynamically linked"), "got: \(reason)")
        }
    }

    func testValidateRejectsTruncatedProgramHeaderTable() throws {
        // Header claims more program headers than the file holds.
        var elf = makeELF(machine: 0xB7, phTypes: [1])
        elf[56] = 200  // e_phnum lies
        let path = try writeTempFile(elf)
        XCTAssertThrowsError(try SanctuaryGuestJail.validateStaticShim(atPath: path))
    }

    func testValidateRejectsAbsurdPhoffWithoutTrapping() throws {
        // A hostile e_phoff near UInt64.max must throw, not overflow-trap.
        var elf = makeELF(machine: 0xB7, phTypes: [1])
        for i in 32..<40 { elf[i] = 0xFF }
        let path = try writeTempFile(elf)
        XCTAssertThrowsError(try SanctuaryGuestJail.validateStaticShim(atPath: path))
    }

    // MARK: - plan building

    func testMakePlanPythonPreambleHasNoMount() throws {
        let plan = try SanctuaryGuestJail.makePlan(
            delivery: .pythonPreamble, command: "/plugin/run", args: ["a"]
        )
        XCTAssertEqual(plan.argv, SanctuaryGuestJail.wrap(command: "/plugin/run", args: ["a"]))
        XCTAssertNil(plan.hostShareDirectory)
        XCTAssertNil(plan.guestMountPoint)
    }

    func testMakePlanStaticBinaryStagesShimAloneReadExec() throws {
        let path = try writeTempFile(makeELF(machine: 0xB7, phTypes: [1]), name: "sanctuary-jail-v1")
        let plan = try SanctuaryGuestJail.makePlan(
            delivery: .staticBinary(hostBinaryPath: path), command: "/plugin/run", args: ["a", "b"]
        )
        defer {
            if let dir = plan.hostShareDirectory {
                try? FileManager.default.removeItem(atPath: dir)
            }
        }

        XCTAssertEqual(plan.argv, ["/run/sanctuary-jail/sanctuary-jail", "--", "/plugin/run", "a", "b"])
        XCTAssertEqual(plan.guestMountPoint, "/run/sanctuary-jail")

        let dir = try XCTUnwrap(plan.hostShareDirectory)
        let contents = try FileManager.default.contentsOfDirectory(atPath: dir)
        XCTAssertEqual(contents, ["sanctuary-jail"], "staged share must expose ONLY the shim")

        let attrs = try FileManager.default.attributesOfItem(atPath: "\(dir)/sanctuary-jail")
        let perms = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        XCTAssertEqual(perms, 0o555, "staged shim must be read+exec only")
    }

    func testMakePlanStaticBinaryFailsClosedOnInvalidShim() throws {
        let path = try writeTempFile(Data("junk".utf8))
        XCTAssertThrowsError(
            try SanctuaryGuestJail.makePlan(
                delivery: .staticBinary(hostBinaryPath: path), command: "/plugin/run", args: []
            )
        )
        XCTAssertThrowsError(
            try SanctuaryGuestJail.makePlan(
                delivery: .staticBinary(hostBinaryPath: "/nope"), command: "/plugin/run", args: []
            )
        )
    }

    // MARK: - launcher config default

    func testLauncherConfigDefaultsToPythonPreambleDelivery() {
        let config = SanctuaryContainerConfig(
            kernelPath: "/k", ociImageReference: "img"
        )
        XCTAssertTrue(config.applyGuestJail)
        XCTAssertEqual(config.guestJailDelivery, .pythonPreamble)
    }
}
