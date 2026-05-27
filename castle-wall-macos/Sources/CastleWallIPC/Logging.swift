//
// Logging.swift
//
// OSLog wrapper. Emit signposts at handshake, IPC connect, IPC frame
// parsed, and fatal-error close. Subsystem is `ai.sanctuaryprotocol.macos.castle-wall`
// so the operator can filter Console.app on the extension's category.
//

import Foundation
import os

public enum CastleWallLog {
    public static let subsystem = "ai.sanctuaryprotocol.macos.castle-wall"

    public static let ipc = Logger(subsystem: subsystem, category: "ipc")
    public static let auth = Logger(subsystem: subsystem, category: "auth")
    public static let lifecycle = Logger(subsystem: subsystem, category: "lifecycle")
}
