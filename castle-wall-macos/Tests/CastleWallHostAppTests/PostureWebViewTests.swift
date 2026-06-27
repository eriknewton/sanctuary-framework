import XCTest
import WebKit
@testable import CastleWallHostApp

/// Security-critical: the embedded posture web view is PINNED to loopback. These
/// tests lock the `isLoopbackURL` gate the navigation delegate uses to cancel
/// any off-machine navigation (Dashboard one-surface spec §3, Delta Review
/// Part C). If this gate ever loosens, the embed could be steered off the local
/// Sanctuary server into a general-purpose browser surface.
final class PostureWebViewTests: XCTestCase {

    func testAllowsLoopbackHttpURL() {
        XCTAssertTrue(PostureWebView.isLoopbackURL(URL(string: "http://127.0.0.1:3501/")!))
        XCTAssertTrue(PostureWebView.isLoopbackURL(URL(string: "http://127.0.0.1:3501/posture")!))
        XCTAssertTrue(PostureWebView.isLoopbackURL(URL(string: "http://127.0.0.1:3501/api/posture/castle-wall")!))
    }

    func testRejectsNonLoopbackHosts() {
        // The classic exfil / phishing vectors the pin exists to stop.
        XCTAssertFalse(PostureWebView.isLoopbackURL(URL(string: "http://example.com/")!))
        XCTAssertFalse(PostureWebView.isLoopbackURL(URL(string: "http://10.0.0.5:3501/")!))
        XCTAssertFalse(PostureWebView.isLoopbackURL(URL(string: "http://attacker.test/posture")!))
    }

    func testRejectsLocalhostHostname() {
        // We pin to the literal 127.0.0.1, NOT "localhost", so a resolver cannot
        // be steered to rebind the name. "localhost" is intentionally rejected.
        XCTAssertFalse(PostureWebView.isLoopbackURL(URL(string: "http://localhost:3501/")!))
    }

    func testRejectsLoopbackHostnameLookalikes() {
        // Subdomain/lookalike hosts that merely contain the loopback string must
        // not pass: the check is exact host equality, not substring.
        XCTAssertFalse(PostureWebView.isLoopbackURL(URL(string: "http://127.0.0.1.evil.test/")!))
        XCTAssertFalse(PostureWebView.isLoopbackURL(URL(string: "http://127.0.0.10/")!))
    }

    func testRejectsNonHttpSchemes() {
        // file:, https-to-elsewhere, custom schemes — none are the local board.
        XCTAssertFalse(PostureWebView.isLoopbackURL(URL(string: "file:///etc/passwd")!))
        XCTAssertFalse(PostureWebView.isLoopbackURL(URL(string: "https://127.0.0.1:3501/")!))
        XCTAssertFalse(PostureWebView.isLoopbackURL(URL(string: "javascript:alert(1)")))
    }

    func testRejectsNilURL() {
        XCTAssertFalse(PostureWebView.isLoopbackURL(nil))
    }

    // MARK: - Subresource pin (WKContentRuleList): block off-loopback fetches

    /// The rule-list JSON must actually compile. A malformed regex or shape
    /// would silently fail to install, leaving the embed without its subresource
    /// pin (the navigation delegate alone does NOT stop subresource loads).
    func testLoopbackRuleListCompiles() throws {
        let expectation = expectation(description: "rule list compiles")
        WKContentRuleListStore.default().compileContentRuleList(
            forIdentifier: "sanctuary-loopback-only-test",
            encodedContentRuleList: PostureWebView.loopbackOnlyRuleListJSON
        ) { ruleList, error in
            XCTAssertNil(error, "rule list must compile: \(String(describing: error))")
            XCTAssertNotNil(ruleList)
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 10.0)
    }

    /// Lock the rule SHAPE the subresource pin depends on: a broad `block` over
    /// every URL, then an `ignore-previous-rules` that re-admits ONLY URLs whose
    /// `http(s)://` host is the loopback literal — keyed on the request URL via
    /// `url-filter`, NOT on the top-level document's domain.
    ///
    /// Why this shape and not `unless-domain`: WebKit scopes `if-domain`/
    /// `unless-domain` on the TOP-LEVEL DOCUMENT's registrable domain, not the
    /// subresource request's host. The board's document IS `127.0.0.1`, so an
    /// `unless-domain: ["127.0.0.1"]` would match the document on every
    /// subresource and suppress the block for ALL of them — a no-op. The "not
    /// loopback" decision must live in `url-filter`, which sees the request URL.
    /// If this shape regresses (the block rule narrows, or the allow regex loses
    /// its `[:/]` boundary and starts re-admitting `127.0.0.1.evil.test`),
    /// off-machine subresources would load again — the exact gap this rule closes.
    func testSubresourcePinIsBlockThenLoopbackAllow() throws {
        let data = Data(PostureWebView.loopbackOnlyRuleListJSON.utf8)
        let rules = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        )
        XCTAssertEqual(rules.count, 2, "broad block, then a loopback-only allow")

        // Rule 0: block every URL.
        let block = try XCTUnwrap(rules.first)
        let blockTrigger = try XCTUnwrap(block["trigger"] as? [String: Any])
        let blockAction = try XCTUnwrap(block["action"] as? [String: Any])
        XCTAssertEqual(blockTrigger["url-filter"] as? String, ".*")
        XCTAssertEqual(blockAction["type"] as? String, "block")
        // The block must NOT be document-scoped — that's the no-op we removed.
        XCTAssertNil(blockTrigger["unless-domain"])
        XCTAssertNil(blockTrigger["if-domain"])

        // Rule 1: re-admit ONLY loopback URLs, scoped on the request URL itself.
        let allow = try XCTUnwrap(rules.last)
        let allowTrigger = try XCTUnwrap(allow["trigger"] as? [String: Any])
        let allowAction = try XCTUnwrap(allow["action"] as? [String: Any])
        XCTAssertEqual(allowAction["type"] as? String, "ignore-previous-rules")
        let allowFilter = try XCTUnwrap(allowTrigger["url-filter"] as? String)
        // Anchored at the URL start, http(s) only, exact loopback literal, and a
        // port/path boundary so lookalikes are NOT re-admitted.
        XCTAssertEqual(allowFilter, #"^https?://127\.0\.0\.1[:/]"#)
        // The allow must also be keyed on the request URL, never the document.
        XCTAssertNil(allowTrigger["unless-domain"])
        XCTAssertNil(allowTrigger["if-domain"])
    }

    /// BEHAVIORAL proof (not just JSON shape): drive WebKit with the real rule
    /// list and assert it actually BLOCKS a subresource whose host is not the
    /// pinned loopback LITERAL, while a same-literal subresource loads — using the
    /// server's own request log as the signal, so the test is deterministic and
    /// portable (no loopback-alias setup, no network reachability variable).
    ///
    /// One in-test HTTP server is bound to `127.0.0.1`. The document is served
    /// from `http://127.0.0.1:<port>/` and references two images:
    ///   - `http://127.0.0.1:<port>/on.gif`  — host is the pinned literal → the
    ///     allow rule re-admits it → the request reaches the server → logged.
    ///   - `http://localhost:<port>/off.gif` — `localhost` RESOLVES to 127.0.0.1
    ///     (so it is equally reachable), but the URL host is NOT the literal
    ///     `127.0.0.1`, so the allow regex does not match → the request is BLOCKED
    ///     and NEVER reaches the server → not logged.
    ///
    /// This is exactly the scenario the old `unless-domain` rule mishandled: that
    /// rule keyed on the DOCUMENT's domain (`127.0.0.1`), so it would have
    /// exempted BOTH images and the server would have logged `/off.gif` too. The
    /// corrected rule keys on each request's own URL, so `/off.gif` must be
    /// blocked. A regression to a document-scoped no-op makes `/off.gif` appear in
    /// the request log and fails this test loudly. The presence of `/on.gif` in
    /// the log is the positive control (the allow rule genuinely re-admits the
    /// literal-loopback subresource rather than blocking everything).
    @MainActor
    func testOffHostSubresourceIsActuallyBlockedWhileLoopbackLoads() throws {
        let server = try LoopbackImageServer(address: "127.0.0.1")
        defer { server.stop() }

        let compiled = expectation(description: "rule list compiles")
        var installed: WKContentRuleList?
        WKContentRuleListStore.default().compileContentRuleList(
            forIdentifier: "sanctuary-loopback-only-behavioral-test",
            encodedContentRuleList: PostureWebView.loopbackOnlyRuleListJSON
        ) { ruleList, error in
            XCTAssertNil(error, "rule list must compile: \(String(describing: error))")
            installed = ruleList
            compiled.fulfill()
        }
        wait(for: [compiled], timeout: 10.0)
        let ruleList = try XCTUnwrap(installed)

        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        config.userContentController.add(ruleList)
        let webView = WKWebView(frame: .init(x: 0, y: 0, width: 100, height: 100),
                                configuration: config)

        let coordinator = SubresourceProbe()
        webView.navigationDelegate = coordinator
        let loaded = expectation(description: "document loaded")
        coordinator.onFinish = { loaded.fulfill() }

        let html = """
        <!doctype html><html><head></head><body>
        <img id="on"  src="http://127.0.0.1:\(server.port)/on.gif">
        <img id="off" src="http://localhost:\(server.port)/off.gif">
        </body></html>
        """
        // Document origin is the pinned loopback host — the exact case where a
        // document-scoped rule would have exempted every subresource.
        webView.loadHTMLString(html, baseURL: URL(string: "http://127.0.0.1:\(server.port)/")!)
        wait(for: [loaded], timeout: 15.0)

        // The top-level `didFinish` callback can fire BEFORE the image
        // subresource fetch lands, so a fixed settle timer would race the
        // positive control. Poll the server's request log for `/on.gif` (the
        // allowed subresource) until it appears, up to a generous cap, instead
        // of asserting after a single wall-clock window. `requestedPaths()` is
        // thread-safe (its own `logQueue.sync`), so we poll on the main queue —
        // staying on the test's actor and avoiding a cross-queue hop.
        let onArrived = expectation(description: "allowed subresource reaches server")
        func pollForOnGif() {
            if server.requestedPaths().contains(where: { $0.contains("/on.gif") }) {
                onArrived.fulfill()
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { pollForOnGif() }
        }
        DispatchQueue.main.async { pollForOnGif() }
        wait(for: [onArrived], timeout: 15.0)

        // `/on.gif` is now logged (positive control). Give the BLOCKED `/off.gif`
        // request a fair chance to (incorrectly) arrive before asserting its
        // absence: if the pin regressed, `/off.gif` would be in flight on the
        // same path the allowed fetch just took, so a brief settle here makes the
        // negative control robust rather than racing the regression.
        let settled = expectation(description: "blocked subresource window settles")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { settled.fulfill() }
        wait(for: [settled], timeout: 5.0)

        let paths = server.requestedPaths()
        XCTAssertTrue(
            paths.contains { $0.contains("/on.gif") },
            "the literal-127.0.0.1 subresource must be re-admitted and reach the server (positive control); log was \(paths)"
        )
        XCTAssertFalse(
            paths.contains { $0.contains("/off.gif") },
            "the non-literal-host (localhost) subresource must be BLOCKED before any request reaches the server; log was \(paths)"
        )
    }
}

/// Minimal navigation delegate used by the behavioral subresource test to know
/// when the document has finished loading before probing it.
private final class SubresourceProbe: NSObject, WKNavigationDelegate {
    var onFinish: (() -> Void)?
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        onFinish?()
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        onFinish?()
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        onFinish?()
    }
}

/// A tiny accept-loop HTTP server bound to a loopback IP, serving a 1x1 GIF for
/// any request and recording each requested path. The request log is the signal
/// the behavioral test reads: a content-rule `block` stops the request before it
/// is ever sent, so a blocked subresource leaves NO log entry, while an allowed
/// one reaches the server and is logged. Pure POSIX sockets; no dependency.
private final class LoopbackImageServer {
    let port: UInt16
    private let listenFD: Int32
    private let queue = DispatchQueue(label: "loopback-image-server")
    private let logQueue = DispatchQueue(label: "loopback-image-server.log")
    private var running = true
    private var paths: [String] = []

    // A minimal valid 1x1 transparent GIF.
    private static let gif: [UInt8] = [
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
        0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b
    ]

    init(address: String) throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ServerError.socket }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0  // OS-assigned ephemeral port
        addr.sin_addr.s_addr = inet_addr(address)
        let bindOK = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindOK == 0 else { close(fd); throw ServerError.bind }
        guard listen(fd, 8) == 0 else { close(fd); throw ServerError.listen }

        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        self.listenFD = fd
        self.port = UInt16(bigEndian: bound.sin_port)

        queue.async { [weak self] in self?.acceptLoop() }
    }

    private func acceptLoop() {
        while running {
            let client = accept(listenFD, nil, nil)
            if client < 0 { break }
            var buf = [UInt8](repeating: 0, count: 2048)
            let n = recv(client, &buf, buf.count, 0)
            if n > 0, let line = String(bytes: buf[0..<n], encoding: .utf8) {
                // First request-line token after the method is the path.
                let parts = line.split(separator: " ", maxSplits: 2)
                if parts.count >= 2 {
                    let path = String(parts[1])
                    logQueue.sync { paths.append(path) }
                }
            }
            let body = Self.gif
            let header = "HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\n"
                + "Content-Length: \(body.count)\r\nConnection: close\r\n\r\n"
            header.utf8CString.withUnsafeBytes { _ = send(client, $0.baseAddress, strlen(header), 0) }
            body.withUnsafeBytes { _ = send(client, $0.baseAddress, body.count, 0) }
            close(client)
        }
    }

    func requestedPaths() -> [String] {
        logQueue.sync { paths }
    }

    func stop() {
        running = false
        close(listenFD)
    }

    enum ServerError: Error { case socket, bind, listen }
}
