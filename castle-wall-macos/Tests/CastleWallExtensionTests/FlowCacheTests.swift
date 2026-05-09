//
// FlowCacheTests.swift
//
// LRU cache behavior. No NetworkExtension dependency. Asserts capacity
// bound, LRU eviction order, manifest-change clear, and cache-hit
// performance characteristic at unit-test scale (hard gate 11).
//

import XCTest
@testable import CastleWallFilter

final class FlowCacheTests: XCTestCase {

    func makeKey(_ host: String, port: Int = 443) -> FlowCacheKey {
        return FlowCacheKey(
            sourceAppIdentifier: "ai.sanctuaryprotocol.test",
            destinationHost: host,
            destinationIp: "1.2.3.4",
            destinationPort: port,
            networkProtocol: .tcp
        )
    }

    func testCacheStoresAndReturnsEntries() {
        let cache = FlowCache(capacity: 3)
        let k = makeKey("a.example.com")
        cache.put(k, .allow(matchedRuleId: "r-1"))
        XCTAssertEqual(cache.get(k), .allow(matchedRuleId: "r-1"))
        XCTAssertEqual(cache.count, 1)
    }

    func testCacheMissReturnsNil() {
        let cache = FlowCache(capacity: 3)
        XCTAssertNil(cache.get(makeKey("missing.example.com")))
    }

    func testCacheUpdateReplacesValue() {
        let cache = FlowCache(capacity: 3)
        let k = makeKey("a.example.com")
        cache.put(k, .allow(matchedRuleId: "r-1"))
        cache.put(k, .drop(matchedRuleId: "r-2"))
        XCTAssertEqual(cache.get(k), .drop(matchedRuleId: "r-2"))
        XCTAssertEqual(cache.count, 1)
    }

    func testCapacityIsBounded() {
        let cache = FlowCache(capacity: 2)
        cache.put(makeKey("a"), .allow(matchedRuleId: "r-a"))
        cache.put(makeKey("b"), .allow(matchedRuleId: "r-b"))
        cache.put(makeKey("c"), .allow(matchedRuleId: "r-c"))
        XCTAssertEqual(cache.count, 2)
    }

    func testLRUEvictsLeastRecentlyUsed() {
        let cache = FlowCache(capacity: 2)
        cache.put(makeKey("a"), .allow(matchedRuleId: "r-a"))
        cache.put(makeKey("b"), .allow(matchedRuleId: "r-b"))
        // Touching `a` makes it most recent; `b` becomes oldest.
        _ = cache.get(makeKey("a"))
        cache.put(makeKey("c"), .allow(matchedRuleId: "r-c"))

        XCTAssertEqual(cache.get(makeKey("a")), .allow(matchedRuleId: "r-a"))
        XCTAssertNil(cache.get(makeKey("b")))
        XCTAssertEqual(cache.get(makeKey("c")), .allow(matchedRuleId: "r-c"))
    }

    func testClearDropsEverything() {
        let cache = FlowCache(capacity: 4)
        cache.put(makeKey("a"), .allow(matchedRuleId: "r-a"))
        cache.put(makeKey("b"), .drop(matchedRuleId: "r-b"))
        cache.clear()
        XCTAssertEqual(cache.count, 0)
        XCTAssertNil(cache.get(makeKey("a")))
        XCTAssertNil(cache.get(makeKey("b")))
    }

    func testContainsDoesNotAffectLRUOrdering() {
        let cache = FlowCache(capacity: 2)
        cache.put(makeKey("a"), .allow(matchedRuleId: "r-a"))
        cache.put(makeKey("b"), .allow(matchedRuleId: "r-b"))
        XCTAssertTrue(cache.contains(makeKey("a")))
        // Adding a third entry should evict the OLDEST, which is `a` (we
        // only contains-checked it; that should not promote it).
        cache.put(makeKey("c"), .allow(matchedRuleId: "r-c"))
        XCTAssertNil(cache.get(makeKey("a")))
    }

    /// Hard gate 11: in-memory cache hit returns under 100µs at unit-test
    /// scale. Real-world p99 measurement lands in Alpha-3.
    func testCacheHitIsUnderOneHundredMicroseconds() {
        let cache = FlowCache(capacity: 1024)
        let k = makeKey("hot.example.com")
        cache.put(k, .allow(matchedRuleId: "hot-1"))

        // Warmup
        for _ in 0..<1000 {
            _ = cache.get(k)
        }

        let iterations = 10_000
        let start = DispatchTime.now()
        for _ in 0..<iterations {
            _ = cache.get(k)
        }
        let elapsed = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
        let perCallNs = Double(elapsed) / Double(iterations)
        // 100 microseconds = 100_000 nanoseconds.
        XCTAssertLessThan(perCallNs, 100_000.0, "per-call cache hit was \(perCallNs)ns; budget 100us")
    }

    func testFlowCacheKeyEquality() {
        let a = FlowCacheKey(
            sourceAppIdentifier: "ai.sanctuaryprotocol.test",
            destinationHost: "a.example.com",
            destinationIp: "1.2.3.4",
            destinationPort: 443,
            networkProtocol: .tcp
        )
        let b = FlowCacheKey(
            sourceAppIdentifier: "ai.sanctuaryprotocol.test",
            destinationHost: "a.example.com",
            destinationIp: "1.2.3.4",
            destinationPort: 443,
            networkProtocol: .tcp
        )
        let differentApp = FlowCacheKey(
            sourceAppIdentifier: "ai.sanctuaryprotocol.other",
            destinationHost: "a.example.com",
            destinationIp: "1.2.3.4",
            destinationPort: 443,
            networkProtocol: .tcp
        )
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, differentApp)
    }
}
