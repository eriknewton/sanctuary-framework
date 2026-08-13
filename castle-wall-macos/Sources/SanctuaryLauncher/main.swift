import Darwin
import Foundation

// The launcher is the signed, absolute entrypoint shared by the installer and
// the harness. Resolve the kernel-reported executable path: argv[0] is caller
// controlled and must never choose which runtime bytes we execute.
var executablePathSize: UInt32 = 0
_ = _NSGetExecutablePath(nil, &executablePathSize)
var executablePathBuffer = [CChar](repeating: 0, count: Int(executablePathSize))
guard _NSGetExecutablePath(&executablePathBuffer, &executablePathSize) == 0,
      let canonicalExecutable = realpath(executablePathBuffer, nil) else {
    FileHandle.standardError.write(Data("Sanctuary signed launcher could not resolve its executable path\n".utf8))
    exit(126)
}
defer { free(canonicalExecutable) }
let executable = URL(fileURLWithPath: String(cString: canonicalExecutable)).standardizedFileURL
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
