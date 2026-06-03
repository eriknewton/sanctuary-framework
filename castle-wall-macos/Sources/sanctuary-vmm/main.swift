import Foundation
import SanctuaryVMM

let exitCode = try await SanctuaryVMMCLI.run()
Foundation.exit(exitCode)
