//
// main.swift
//
// Extension entry point. sysextd loads this binary when the host app
// requests filter activation via NEFilterManager. For the NetworkExtension
// framework to actually dispatch the NEFilterDataProvider subclass declared
// in Info.plist NSExtensionPrincipalClass, this entry point MUST call
// `NEProvider.startSystemExtensionMode()`. Without that call, sysextd loads
// the binary, the main runloop idles, and startFilter is never invoked --
// no flows get intercepted and the filter session stays in [inactive]
// state. See LuLu (objective-see/LuLu) main.m for the canonical pattern.
//

import Foundation
import NetworkExtension
import CastleWallIPC
import CastleWallFilter

// Touch the principal class so the linker keeps the symbol live in the
// executable target. Real instantiation is via NSExtensionPrincipalClass
// lookup performed by the NetworkExtension framework after
// startSystemExtensionMode() arms it.
_ = CastleWallFilterProvider.self

CastleWallLog.lifecycle.info(
    "CastleWallExtension main.swift entered; calling NEProvider.startSystemExtensionMode"
)

// Hand off to the NetworkExtension framework. This is the call that causes
// sysextd to dispatch our NEFilterDataProvider subclass when the OS arms
// the content filter. Required on macOS for any sysext-mode NEProvider.
NEProvider.startSystemExtensionMode()

// Block forever, processing dispatch events. The NEProvider runtime drives
// the actual filter callbacks (startFilter, handleNewFlow, stopFilter)
// via the dispatch queues it owns.
dispatchMain()
