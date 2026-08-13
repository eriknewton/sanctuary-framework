import Darwin
import Foundation

// The launcher is the signed, absolute entrypoint shared by the installer and
// the harness. It never consults PATH and strips Node preload/search overrides
// before entering the app-sealed JavaScript runtime.
let executable = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
let contents = executable.deletingLastPathComponent().deletingLastPathComponent()
let node = contents.appendingPathComponent("Resources/boot-runtime/node").path
let cli = contents.appendingPathComponent("Resources/cli-runtime/dist/cli.js").path

unsetenv("NODE_OPTIONS")
unsetenv("NODE_PATH")

var arguments = [node, cli]
arguments.append(contentsOf: CommandLine.arguments.dropFirst())
let cArguments = arguments.map { strdup($0) } + [nil]
defer { cArguments.dropLast().forEach { free($0) } }

execv(node, cArguments)
let message = "Sanctuary signed launcher could not execute its sealed runtime: \(String(cString: strerror(errno)))\n"
FileHandle.standardError.write(Data(message.utf8))
exit(126)
