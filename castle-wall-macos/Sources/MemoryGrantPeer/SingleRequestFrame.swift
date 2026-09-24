import Foundation

public enum SingleRequestFrameError: Error, Equatable {
    case invalidLength
    case tooLarge
    case trailingBytes
    case incomplete
    case terminal
}

/// Incrementally decode one opaque request: a four-byte unsigned big-endian length,
/// followed by that many payload bytes, followed by write-side EOF. This is a new
/// broker framing primitive, not the CastleWallIPC protocol. It performs no JSON
/// validation, authorization, I/O, or writes. A future consumer must validate the
/// payload schema and apply its own admission limit and absolute read deadline.
public struct SingleRequestFrame {
    public static let headerBytes = MemoryLayout<UInt32>.size
    /// A request control message is limited to 64 KiB; bulk file content needs a
    /// separately designed transport and must not raise this bound implicitly.
    public static let maximumPayloadBytes = 64 * 1024

    private enum State { case header, body(Int), finished, failed }
    private var state: State = .header
    private var buffer = Data()

    public init() {}

    /// Retained input never exceeds the header plus maximumPayloadBytes.
    public var bufferedByteCount: Int { buffer.count }

    /// Append a bounded read. Any parse failure poisons this decoder permanently.
    /// The caller must discard the connection on failure, never restart decoding it.
    public mutating func append(_ bytes: Data) throws {
        switch state {
        case .finished, .failed: throw SingleRequestFrameError.terminal
        case .header, .body: break
        }
        // Reject before copying or iterating caller input; a huge chunk cannot grow
        // retained memory or cause work proportional to its attacker-selected size.
        guard bytes.count <= Self.headerBytes + Self.maximumPayloadBytes - buffer.count else {
            throw fail(.tooLarge)
        }
        buffer.append(bytes)
        if case .header = state, buffer.count >= Self.headerBytes {
            let length = buffer.prefix(Self.headerBytes).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard length > 0 else { throw fail(.invalidLength) }
            guard length <= Self.maximumPayloadBytes else { throw fail(.tooLarge) }
            state = .body(Int(length))
        }
        if case let .body(length) = state, buffer.count > Self.headerBytes + length {
            throw fail(.trailingBytes)
        }
    }

    /// Call only after transport EOF, not when a read happens to return a full frame.
    /// Waiting for EOF prevents an accepted prefix from hiding a second request.
    public mutating func finishAtEOF() throws -> Data {
        switch state {
        case .finished, .failed: throw SingleRequestFrameError.terminal
        case .header: throw fail(.incomplete)
        case let .body(length):
            guard buffer.count == Self.headerBytes + length else { throw fail(.incomplete) }
            let payload = Data(buffer.dropFirst(Self.headerBytes))
            buffer = Data()
            state = .finished
            return payload
        }
    }

    private mutating func fail(_ error: SingleRequestFrameError) -> SingleRequestFrameError {
        state = .failed
        buffer = Data()
        return error
    }
}
