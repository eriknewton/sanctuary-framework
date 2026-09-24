import Darwin

/// Failures are terminal for the caller's connection; none permits a fallback identity.
public enum UnixPeerError: Error, Equatable {
    case invalidExpectedUID
    case inspectionFailed
    case unsupportedSocket
    case unexpectedUID
}

/// A kernel-reported connection identity, not evidence of operator consent or confinement.
public struct UnixPeerIdentity: Equatable {
    public let effectiveUID: uid_t
    public let effectiveGID: gid_t

    fileprivate init(effectiveUID: uid_t, effectiveGID: gid_t) {
        self.effectiveUID = effectiveUID
        self.effectiveGID = effectiveGID
    }
}

/// Infrastructure for a future protected broker. This library grants no memory access.
public enum UnixPeerVerifier {
    /// Verify the peer on an already connected Unix stream socket against a trusted UID.
    /// The caller must exclusively own this descriptor through verification and use: do
    /// not close, replace, or concurrently reuse it. Select expectedUID from protected
    /// configuration, never from a request. A same-UID agent remains indistinguishable
    /// from its operator here. On any error, close the connection without processing it.
    public static func requirePeer(socket: Int32, expectedUID: uid_t) throws -> UnixPeerIdentity {
        guard expectedUID != uid_t.max else { throw UnixPeerError.invalidExpectedUID }

        var type: Int32 = 0
        var typeLength = socklen_t(MemoryLayout.size(ofValue: type))
        guard getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &typeLength) == 0,
              typeLength == MemoryLayout.size(ofValue: type) else {
            throw UnixPeerError.inspectionFailed
        }
        guard type == SOCK_STREAM else { throw UnixPeerError.unsupportedSocket }

        var address = sockaddr_storage()
        var addressLength = socklen_t(MemoryLayout.size(ofValue: address))
        let connected = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getpeername(socket, $0, &addressLength)
            }
        }
        guard connected == 0,
              addressLength >= MemoryLayout<sa_family_t>.size + MemoryLayout<UInt8>.size,
              addressLength <= MemoryLayout.size(ofValue: address) else {
            throw UnixPeerError.inspectionFailed
        }
        guard address.ss_family == sa_family_t(AF_UNIX) else {
            throw UnixPeerError.unsupportedSocket
        }

        var uid = uid_t.max
        var gid = gid_t.max
        // Darwin getpeereid uses LOCAL_PEERCRED: only kernel connection credentials
        // carry identity. Paths, JSON fields, process names, and claimed UIDs never do.
        guard getpeereid(socket, &uid, &gid) == 0, uid != uid_t.max, gid != gid_t.max else {
            throw UnixPeerError.inspectionFailed
        }
        guard uid == expectedUID else { throw UnixPeerError.unexpectedUID }
        return UnixPeerIdentity(effectiveUID: uid, effectiveGID: gid)
    }
}
