//
// main.swift
//
// Extension entry point. NEProvider subclasses register themselves via the
// Info.plist `NSExtensionPrincipalClass` key when bundled as a system
// extension. SwiftPM produces an executable here so the foundation scope
// can verify the type compiles and links NetworkExtension; Alpha-4 install
// flow wraps it into the .systemextension bundle.
//

import Foundation
import CastleWallIPC
import CastleWallFilter

// Touch the principal class so the linker keeps the symbol live in the
// executable target. Real registration is via NSExtensionPrincipalClass in
// Info.plist at bundle time.
_ = CastleWallFilterProvider.self

CastleWallLog.lifecycle.info("CastleWallExtension main.swift entered; idling for sysextd dispatch")

// Run a no-op loop. The actual extension lifecycle is driven by NEProvider
// callbacks once the bundle is loaded by `sysextd`.
RunLoop.main.run()
