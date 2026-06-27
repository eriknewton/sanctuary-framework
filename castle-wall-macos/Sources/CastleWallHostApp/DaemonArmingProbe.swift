import Foundation
import CastleWallIPC
import CastleWallSigner

protocol DaemonHandshakeClient {
    func start() async throws -> HandshakeIdentity
    func close()
}

extension IPCClient: DaemonHandshakeClient {}

enum DaemonArmingProbe {
    static func authenticatedDaemonPresent(
        pinnedPublicKeyPath: String = SignerConstants.pinnedPublicKeyPath,
        resolveSocketPath: () -> String? = {
            SocketPath.activeDaemonSocketPathForArming()
        },
        loadPinnedPublicKey: (URL) throws -> Data = Auth.loadPinnedPublicKey,
        makeClient: @escaping (String, Data) -> DaemonHandshakeClient = { path, pinnedKey in
            IPCClient(
                options: IPCClientOptions(path: path, handshakeTimeoutSeconds: 1.0),
                pinnedPublicKey: pinnedKey
            )
        }
    ) async -> Bool {
        guard let socketPath = resolveSocketPath() else {
            return false
        }
        let pinnedKey: Data
        do {
            pinnedKey = try loadPinnedPublicKey(URL(fileURLWithPath: pinnedPublicKeyPath))
        } catch {
            return false
        }

        let client = makeClient(socketPath, pinnedKey)
        defer { client.close() }
        do {
            _ = try await client.start()
            return true
        } catch {
            return false
        }
    }
}
