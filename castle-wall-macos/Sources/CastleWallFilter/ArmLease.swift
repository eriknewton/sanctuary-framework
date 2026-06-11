import Foundation

public final class ArmLease {
    public static let failOpenRuleId = "fail_open_deadman"

    private let lock = NSLock()
    private var armed = false
    private var leaseExpiresAt: Date?
    private var heartbeatExpiresAt: Date?
    private let now: () -> Date

    public init(now: @escaping () -> Date = Date.init) {
        self.now = now
    }

    public func update(_ update: ArmLeaseUpdate) {
        lock.lock()
        defer { lock.unlock() }

        armed = update.armed
        guard update.armed else {
            leaseExpiresAt = nil
            heartbeatExpiresAt = nil
            return
        }

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
            leaseExpiresAt: leaseExpiresAt,
            heartbeatExpiresAt: heartbeatExpiresAt,
            failOpenReason: failOpenReasonLocked(now())
        )
    }

    private func failOpenReasonLocked(_ current: Date) -> String? {
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
    public let ttlSeconds: UInt32?
    public let heartbeatIntervalSeconds: UInt32

    public init(
        armed: Bool,
        ttlSeconds: UInt32?,
        heartbeatIntervalSeconds: UInt32
    ) {
        self.armed = armed
        self.ttlSeconds = ttlSeconds
        self.heartbeatIntervalSeconds = heartbeatIntervalSeconds
    }
}

public struct ArmLeaseSnapshot: Equatable {
    public let armed: Bool
    public let leaseExpiresAt: Date?
    public let heartbeatExpiresAt: Date?
    public let failOpenReason: String?
}
