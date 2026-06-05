//
// CodeRequirementTests.swift
//
// The caller code-requirement string is the load-bearing input to the helper's
// XPC peer check (§4.4). A typo here silently weakens (or breaks) the gate, so we
// pin its exact shape and confirm it compiles into a real SecRequirement.
//

import XCTest
import Security
@testable import CastleWallSigner

final class CodeRequirementTests: XCTestCase {

    func testRequirementStringHasExpectedShape() {
        let req = CodeRequirement.signerClientRequirement()
        XCTAssertEqual(
            req,
            "anchor apple generic and certificate leaf[subject.OU] = \"YFQSWQ9BJN\" and identifier \"ai.sanctuaryprotocol.macos.castle-wall.signer-client\""
        )
    }

    func testRequirementPinsTeamAndIdentifier() {
        let req = CodeRequirement.signerClientRequirement()
        XCTAssertTrue(req.contains("anchor apple generic"))
        XCTAssertTrue(req.contains(SignerConstants.teamID))
        XCTAssertTrue(req.contains(SignerConstants.signerClientIdentifier))
    }

    func testRequirementCompilesToSecRequirement() {
        let req = CodeRequirement.signerClientRequirement()
        XCTAssertNotNil(
            CodeRequirement.makeRequirement(req),
            "requirement string must compile to a SecRequirement"
        )
    }

    func testCustomTeamAndIdentifierAreInterpolated() {
        let req = CodeRequirement.signerClientRequirement(
            teamID: "ABCDE12345",
            identifier: "com.example.client"
        )
        XCTAssertTrue(req.contains("ABCDE12345"))
        XCTAssertTrue(req.contains("com.example.client"))
        XCTAssertNotNil(CodeRequirement.makeRequirement(req))
    }

    func testGarbageRequirementFailsToCompile() {
        XCTAssertNil(CodeRequirement.makeRequirement("this is not a requirement >>>"))
    }
}
