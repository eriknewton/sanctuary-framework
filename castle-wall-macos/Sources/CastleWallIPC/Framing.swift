//
// Framing.swift
//
// LSP-style content-length framing parser and encoder.
//
// Mirrors `server/src/castle-wall/ipc/framing.ts` and
// `castle-wall-daemon/src/ipc/framing.rs` byte-for-byte. The cross-language
// vector suite uses identical fixed payloads to assert all three
// implementations agree.
//
// Frame shape: `Content-Length: <n>\r\n\r\n<n bytes UTF-8 JSON>`.
//

import Foundation

/// Result of a single parse step.
public enum FramingParseStep: Equatable {
    /// A full frame was decoded.
    case complete(body: String, consumedBytes: Int)
    /// More bytes are needed before a frame can be decoded.
    case needMore
    /// Hard, non-recoverable framing error. Caller closes the connection.
    case error(reason: String)
}

public enum Framing {
    private static let headerEnd: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A] // "\r\n\r\n"

    /// Encode a UTF-8 JSON body into an LSP-framed buffer.
    public static func frame(_ jsonBody: String) -> Data {
        let bodyBytes = Array(jsonBody.utf8)
        let header = "\(CastleWallConstants.ipcContentLengthHeader): \(bodyBytes.count)\r\n\r\n"
        let headerBytes = Array(header.utf8)
        var out = Data(capacity: headerBytes.count + bodyBytes.count)
        out.append(contentsOf: headerBytes)
        out.append(contentsOf: bodyBytes)
        return out
    }

    /// Parse one frame from `buf`. Caller is responsible for accumulating
    /// bytes across reads and slicing out `consumedBytes` after a `.complete`
    /// result.
    public static func parseFrame(_ buf: Data) -> FramingParseStep {
        guard let headerEndIdx = findSubsequence(buf, headerEnd) else {
            return .needMore
        }

        let headerSlice = buf[buf.startIndex..<(buf.startIndex + headerEndIdx)]
        guard let headerText = String(data: headerSlice, encoding: .utf8) else {
            return .error(reason: "header is not valid UTF-8")
        }

        var contentLength: Int? = nil
        for line in headerText.components(separatedBy: "\r\n") where !line.isEmpty {
            guard let colonIdx = line.firstIndex(of: ":") else {
                return .error(reason: "malformed header line: \(line)")
            }
            let name = line[line.startIndex..<colonIdx].trimmingCharacters(in: .whitespaces)
            let valueStart = line.index(after: colonIdx)
            let value = line[valueStart...].trimmingCharacters(in: .whitespaces)
            if name.caseInsensitiveCompare(CastleWallConstants.ipcContentLengthHeader) == .orderedSame {
                guard let parsed = Int(value), parsed >= 0 else {
                    return .error(reason: "invalid Content-Length value: \(value)")
                }
                contentLength = parsed
            }
        }

        guard let length = contentLength else {
            return .error(reason: "missing Content-Length header")
        }

        let bodyStart = headerEndIdx + headerEnd.count
        let totalNeeded = bodyStart + length
        if buf.count < totalNeeded {
            return .needMore
        }

        let bodySlice = buf[(buf.startIndex + bodyStart)..<(buf.startIndex + totalNeeded)]
        guard let body = String(data: bodySlice, encoding: .utf8) else {
            return .error(reason: "body is not valid UTF-8")
        }

        return .complete(body: body, consumedBytes: totalNeeded)
    }

    /// Find the first index of `needle` in `haystack`. Returns nil if absent.
    private static func findSubsequence(_ haystack: Data, _ needle: [UInt8]) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else {
            return nil
        }
        let limit = haystack.count - needle.count
        for i in 0...limit {
            var matched = true
            for j in 0..<needle.count {
                if haystack[haystack.startIndex + i + j] != needle[j] {
                    matched = false
                    break
                }
            }
            if matched {
                return i
            }
        }
        return nil
    }
}
