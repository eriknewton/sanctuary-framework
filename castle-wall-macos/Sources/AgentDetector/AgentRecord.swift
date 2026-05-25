import Foundation

/// A detected AI agent on the local machine.
public struct AgentRecord: Identifiable, Equatable {
    public let id: String
    public let name: String
    public let binaryPath: String?
    public let version: String?
    public let isRunning: Bool
    public let harnessFlag: String?
    public let suggestedProtectDefault: Bool

    public init(
        id: String,
        name: String,
        binaryPath: String? = nil,
        version: String? = nil,
        isRunning: Bool = false,
        harnessFlag: String? = nil,
        suggestedProtectDefault: Bool = true
    ) {
        self.id = id
        self.name = name
        self.binaryPath = binaryPath
        self.version = version
        self.isRunning = isRunning
        self.harnessFlag = harnessFlag
        self.suggestedProtectDefault = suggestedProtectDefault
    }
}
