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

    /// SHA-256 (lowercase hex) of in-memory data, via a temp file through the
    /// same digest implementation production uses.
    private func sha256Hex(_ data: Data) throws -> String {
        let path = try writeTempFile(data, name: "digest-input")
        return try SanctuaryImageIntegrity.computeDigest(at: URL(fileURLWithPath: path))
    }

    /// A syntactically valid 64-hex pin that will not match any fixture.
    private let wrongPin = String(repeating: "ab", count: 32)

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
            try SanctuaryGuestJail.parseDelivery(
                mode: nil, staticBinaryPath: nil, staticBinarySHA256: nil
            ),
            .pythonPreamble
        )
        XCTAssertEqual(
            try SanctuaryGuestJail.parseDelivery(
                mode: "python-preamble", staticBinaryPath: nil, staticBinarySHA256: nil
            ),
            .pythonPreamble
        )
    }

    func testParseDeliveryStaticBinary() throws {
        XCTAssertEqual(
            try SanctuaryGuestJail.parseDelivery(
                mode: "static-binary", staticBinaryPath: "/x/jail", staticBinarySHA256: wrongPin
            ),
            .staticBinary(hostBinaryPath: "/x/jail", expectedSHA256: wrongPin)
        )
    }

    func testParseDeliveryNormalizesPinToLowercase() throws {
        let upper = wrongPin.uppercased()
        XCTAssertEqual(
            try SanctuaryGuestJail.parseDelivery(
                mode: "static-binary", staticBinaryPath: "/x/jail", staticBinarySHA256: upper
            ),
            .staticBinary(hostBinaryPath: "/x/jail", expectedSHA256: wrongPin)
        )
    }

    func testParseDeliveryStaticBinaryWithoutPathFailsClosed() {
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(
                mode: "static-binary", staticBinaryPath: nil, staticBinarySHA256: wrongPin
            )
        )
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(
                mode: "static-binary", staticBinaryPath: "", staticBinarySHA256: wrongPin
            )
        )
    }

    func testParseDeliveryStaticBinaryWithoutHashFailsClosed() {
        // No hash, no static delivery: the pin is a REQUIRED precondition.
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(
                mode: "static-binary", staticBinaryPath: "/x/jail", staticBinarySHA256: nil
            )
        ) { error in
            XCTAssertTrue(
                "\(error)".contains("staticJailBinarySHA256"),
                "error must name the missing precondition: \(error)"
            )
        }
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(
                mode: "static-binary", staticBinaryPath: "/x/jail", staticBinarySHA256: ""
            )
        )
    }

    func testParseDeliveryStaticBinaryWithMalformedHashFailsClosed() {
        for malformed in [
            "deadbeef",                                   // too short
            wrongPin + "ab",                              // too long
            String(repeating: "g", count: 64),            // non-hex
            "sha256:" + String(repeating: "ab", count: 32) // prefixed form rejected
        ] {
            XCTAssertThrowsError(
                try SanctuaryGuestJail.parseDelivery(
                    mode: "static-binary", staticBinaryPath: "/x/jail", staticBinarySHA256: malformed
                ),
                "malformed pin '\(malformed)' must be refused"
            )
        }
    }

    func testParseDeliveryUnknownModeFailsClosed() {
        // An unknown mode must never silently fall back to python delivery.
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(
                mode: "none", staticBinaryPath: nil, staticBinarySHA256: nil
            )
        )
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(
                mode: "Static-Binary", staticBinaryPath: "/x/jail", staticBinarySHA256: wrongPin
            )
        )
    }

    func testParseDeliveryPathOrHashWithPythonModeFailsClosed() {
        // Ambiguous intent (static-delivery fields but python mode) is
        // rejected rather than guessed.
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(
                mode: nil, staticBinaryPath: "/x/jail", staticBinarySHA256: nil
            )
        )
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(
                mode: "python-preamble", staticBinaryPath: "/x/jail", staticBinarySHA256: nil
            )
        )
        XCTAssertThrowsError(
            try SanctuaryGuestJail.parseDelivery(
                mode: "python-preamble", staticBinaryPath: nil, staticBinarySHA256: wrongPin
            )
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
        let shim = makeELF(machine: 0xB7, phTypes: [1])
        let path = try writeTempFile(shim, name: "sanctuary-jail-v1")
        let plan = try SanctuaryGuestJail.makePlan(
            delivery: .staticBinary(hostBinaryPath: path, expectedSHA256: try sha256Hex(shim)),
            command: "/plugin/run",
            args: ["a", "b"]
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
        // Correct pin but structurally invalid file: the secondary ELF sanity
        // layer still refuses (hash alone is not sufficient to launch).
        let junk = Data("junk".utf8)
        let path = try writeTempFile(junk)
        XCTAssertThrowsError(
            try SanctuaryGuestJail.makePlan(
                delivery: .staticBinary(hostBinaryPath: path, expectedSHA256: try sha256Hex(junk)),
                command: "/plugin/run",
                args: []
            )
        ) { error in
            guard case SanctuaryGuestJailError.staticBinaryInvalid = error else {
                return XCTFail("expected staticBinaryInvalid, got \(error)")
            }
        }
        XCTAssertThrowsError(
            try SanctuaryGuestJail.makePlan(
                delivery: .staticBinary(hostBinaryPath: "/nope", expectedSHA256: wrongPin),
                command: "/plugin/run",
                args: []
            )
        ) { error in
            guard case SanctuaryGuestJailError.staticBinaryMissing = error else {
                return XCTFail("expected staticBinaryMissing, got \(error)")
            }
        }
    }

    // MARK: - static shim SHA-256 authentication (codex CRITICAL fix)

    func testMakePlanRefusesHostileButValidStaticELFWithWrongPin() throws {
        // THE codex-review CRITICAL: a hostile static aarch64 ELF passes
        // every shape check, so shape must not be sufficient. With a pin
        // that does not match the hostile bytes, launch is refused.
        let hostileShim = makeELF(machine: 0xB7, phTypes: [1, 1])
        let hostilePin = try sha256Hex(hostileShim)
        let path = try writeTempFile(hostileShim, name: "hostile-shim")
        XCTAssertNoThrow(
            try SanctuaryGuestJail.validateStaticShim(atPath: path),
            "precondition: the hostile ELF must pass the shape checks for this test to bite"
        )
        XCTAssertThrowsError(
            try SanctuaryGuestJail.makePlan(
                delivery: .staticBinary(hostBinaryPath: path, expectedSHA256: wrongPin),
                command: "/plugin/run",
                args: []
            )
        ) { error in
            guard case SanctuaryGuestJailError.staticBinaryHashMismatch(_, let expected, let actual) = error else {
                return XCTFail("expected staticBinaryHashMismatch, got \(error)")
            }
            XCTAssertEqual(expected, wrongPin)
            XCTAssertEqual(actual, hostilePin)
        }
        // And nothing staged is left behind for a later launch to pick up.
        let leftovers = try FileManager.default
            .contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)
            .filter { $0.hasPrefix("sanctuary-jail-share-") }
        for dir in leftovers {
            let staged = FileManager.default.temporaryDirectory
                .appendingPathComponent(dir).appendingPathComponent("sanctuary-jail")
            if let data = FileManager.default.contents(atPath: staged.path) {
                XCTAssertNotEqual(data, hostileShim, "rejected shim must not remain staged")
            }
        }
    }

    func testMakePlanAcceptsCorrectPinCaseInsensitively() throws {
        let shim = makeELF(machine: 0xB7, phTypes: [1])
        let path = try writeTempFile(shim)
        let pin = try sha256Hex(shim)
        for variant in [pin, pin.uppercased()] {
            let plan = try SanctuaryGuestJail.makePlan(
                delivery: .staticBinary(hostBinaryPath: path, expectedSHA256: variant),
                command: "/plugin/run",
                args: []
            )
            defer {
                if let dir = plan.hostShareDirectory {
                    try? FileManager.default.removeItem(atPath: dir)
                }
            }
            XCTAssertNotNil(plan.hostShareDirectory)
        }
    }

    func testMakePlanRefusesAbsentOrMalformedPinViaDirectAPI() throws {
        // Direct Swift-API construction (bypassing parseDelivery) must still
        // fail closed on a missing/malformed pin: no hash, no static delivery.
        let shim = makeELF(machine: 0xB7, phTypes: [1])
        let path = try writeTempFile(shim)
        for badPin in ["", "deadbeef", String(repeating: "g", count: 64)] {
            XCTAssertThrowsError(
                try SanctuaryGuestJail.makePlan(
                    delivery: .staticBinary(hostBinaryPath: path, expectedSHA256: badPin),
                    command: "/plugin/run",
                    args: []
                ),
                "pin '\(badPin)' must be refused"
            ) { error in
                guard case SanctuaryGuestJailError.invalidDeliveryConfiguration = error else {
                    return XCTFail("expected invalidDeliveryConfiguration, got \(error)")
                }
            }
        }
    }

    func testHashIsComputedOnStagedCopySourceSwapAfterStagingCannotBypass() throws {
        // TOCTOU: the pin is verified against the STAGED copy, and the source
        // is read exactly once at staging. Swapping the source afterwards
        // must change neither what was hashed nor what the guest would run.
        let trustedShim = makeELF(machine: 0xB7, phTypes: [1])
        let hostileShim = makeELF(machine: 0xB7, phTypes: [1, 1, 1])
        let pin = try sha256Hex(trustedShim)
        let path = try writeTempFile(trustedShim, name: "sanctuary-jail")

        let plan = try SanctuaryGuestJail.makePlan(
            delivery: .staticBinary(hostBinaryPath: path, expectedSHA256: pin),
            command: "/plugin/run",
            args: []
        )
        defer {
            if let dir = plan.hostShareDirectory {
                try? FileManager.default.removeItem(atPath: dir)
            }
        }

        // Adversary swaps the source AFTER staging.
        try hostileShim.write(to: URL(fileURLWithPath: path))

        let dir = try XCTUnwrap(plan.hostShareDirectory)
        let stagedPath = "\(dir)/sanctuary-jail"
        let stagedBytes = try XCTUnwrap(FileManager.default.contents(atPath: stagedPath))
        XCTAssertEqual(stagedBytes, trustedShim, "guest must see the bytes that were pinned, not the swap")
        XCTAssertEqual(
            try SanctuaryImageIntegrity.computeDigest(at: URL(fileURLWithPath: stagedPath)),
            pin,
            "staged copy must still match the pin after a source swap"
        )
    }

    func testSymlinkSourceIsResolvedOnceAtStagingRetargetCannotBypass() throws {
        // A symlink source must not let an adversary retarget between hash
        // and mount: staging reads the bytes once (symlink resolved at that
        // instant) and everything downstream uses the staged regular file.
        let trustedShim = makeELF(machine: 0xB7, phTypes: [1])
        let hostileShim = makeELF(machine: 0xB7, phTypes: [1, 1])
        let trustedPath = try writeTempFile(trustedShim, name: "trusted-shim")
        let hostilePath = try writeTempFile(hostileShim, name: "hostile-shim")
        let linkPath = (trustedPath as NSString).deletingLastPathComponent + "/shim-link"
        try FileManager.default.createSymbolicLink(
            atPath: linkPath, withDestinationPath: trustedPath
        )

        let pin = try sha256Hex(trustedShim)
        let plan = try SanctuaryGuestJail.makePlan(
            delivery: .staticBinary(hostBinaryPath: linkPath, expectedSHA256: pin),
            command: "/plugin/run",
            args: []
        )
        defer {
            if let dir = plan.hostShareDirectory {
                try? FileManager.default.removeItem(atPath: dir)
            }
        }

        // Adversary retargets the symlink AFTER staging.
        try FileManager.default.removeItem(atPath: linkPath)
        try FileManager.default.createSymbolicLink(
            atPath: linkPath, withDestinationPath: hostilePath
        )

        let dir = try XCTUnwrap(plan.hostShareDirectory)
        let stagedBytes = try XCTUnwrap(FileManager.default.contents(atPath: "\(dir)/sanctuary-jail"))
        XCTAssertEqual(stagedBytes, trustedShim, "staged copy must be a regular file, immune to retargeting")
        let attrs = try FileManager.default.attributesOfItem(atPath: "\(dir)/sanctuary-jail")
        XCTAssertEqual(attrs[.type] as? FileAttributeType, .typeRegular)
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
