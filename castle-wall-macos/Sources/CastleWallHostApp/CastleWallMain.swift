import Foundation
import SwiftUI

/// Process entry point. Routes `--headless` invocations to the no-WindowServer
/// filter CLI (arm/disarm/status over SSH) and everything else to the SwiftUI
/// app. The split matters: the headless path must run before any AppKit/
/// SwiftUI initialization, or a GUI-less session (SSH) would abort at launch.
@main
enum CastleWallMain {
    static func main() {
        switch HeadlessFilterCLI.parse(CommandLine.arguments) {
        case nil:
            CastleWallHostApp.main()
        case let .usageError(message):
            FileHandle.standardError.write(Data("\(message)\n".utf8))
            exit(HeadlessFilterCLI.ExitCode.usage.rawValue)
        case let .invocation(invocation):
            exit(HeadlessFilterCLI.run(invocation).rawValue)
        }
    }
}
