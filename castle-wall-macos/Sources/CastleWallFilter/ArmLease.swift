import Foundation

public final class ArmLease {
    public static let failOpenRuleId = "fail_open_deadman"

    private let lock = NSLock()
    private var armed = false
    private var revoked = false
    private var leaseExpiresAt: Date?
    private var heartbeatExpiresAt: Date?
    private let now: () -> Date

    public init(now: @escaping () -> Date = Date.init) {
        self.now = now
    }

    public func update(_ update: ArmLeaseUpdate) {
        lock.lock()
        defer { lock.unlock() }

        if update.revoked {
            armed = false
            revoked = true
            leaseExpiresAt = nil
            heartbeatExpiresAt = nil
            return
        }

        armed = update.armed
        guard update.armed else {
            leaseExpiresAt = nil
            heartbeatExpiresAt = nil
            return
        }

        revoked = false
        let current = now()
        if let ttlSeconds = update.ttlSeconds {
            leaseExpiresAt = current.addingTimeInterval(TimeInterval(ttlSeconds))
        } else {
            leaseExpiresAt = nil
        }
        heartbeatExpiresAt = current.addingTimeInterval(
            TimeInterval(update.heartbeatIntervalSeconds * 2)
        )
    }

    public func failOpenReason() -> String? {
        lock.lock()
        defer { lock.unlock() }

        if revoked {
            return "lease_revoked"
        }
        guard armed else {
            return nil
        }

        let current = now()
        if let leaseExpiresAt, current >= leaseExpiresAt {
            return "ttl_expired"
        }
        if let heartbeatExpiresAt, current >= heartbeatExpiresAt {
            return "heartbeat_stopped"
        }
        return nil
    }

    public func snapshot() -> ArmLeaseSnapshot {
        lock.lock()
        defer { lock.unlock() }

        return ArmLeaseSnapshot(
            armed: armed,
            revoked: revoked,
            leaseExpiresAt: leaseExpiresAt,
            heartbeatExpiresAt: heartbeatExpiresAt,
            failOpenReason: failOpenReasonLocked(now())
        )
    }

    private func failOpenReasonLocked(_ current: Date) -> String? {
        if revoked {
            return "lease_revoked"
        }
        guard armed else {
            return nil
        }
        if let leaseExpiresAt, current >= leaseExpiresAt {
            return "ttl_expired"
        }
        if let heartbeatExpiresAt, current >= heartbeatExpiresAt {
            return "heartbeat_stopped"
        }
        return nil
    }
}

public struct ArmLeaseUpdate: Equatable {
    public let armed: Bool
    public let revoked: Bool
    public let ttlSeconds: UInt32?
    public let heartbeatIntervalSeconds: UInt32

    public init(
        armed: Bool,
        revoked: Bool = false,
        ttlSeconds: UInt32?,
        heartbeatIntervalSeconds: UInt32
    ) {
        self.armed = armed
        self.revoked = revoked
        self.ttlSeconds = ttlSeconds
        self.heartbeatIntervalSeconds = heartbeatIntervalSeconds
    }
}

public struct ArmLeaseSnapshot: Equatable {
    public let armed: Bool
    public let revoked: Bool
    public let leaseExpiresAt: Date?
    public let heartbeatExpiresAt: Date?
    public let failOpenReason: String?
}
