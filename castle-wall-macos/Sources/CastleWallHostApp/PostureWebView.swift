import SwiftUI
import WebKit

/// Embedded, loopback-pinned web view that renders the one Sanctuary posture
/// board *inside* the native app (Delta Review Part C, Option 2 — the durable
/// answer; supersedes the PR #643 browser-handoff seam).
///
/// Why a web view and not a SwiftUI rebuild: the posture board is the single
/// source of "what is protected / exposed / armed" truth, and every
/// "never fake green" invariant already lives — proven and reviewed — in the
/// TypeScript posture code (`posture.ts`, `feature-health.ts`). Re-rendering it
/// natively (Option 3) would fork that honesty model into a second code path
/// that can disagree on green. Embedding the real page keeps ONE honesty model.
///
/// Security posture (Dashboard one-surface spec §3, Delta Review Part C). The
/// embedded surface is confined to the local machine by TWO independent gates,
/// because navigation and subresources are different load types in WebKit:
///   - TOP-LEVEL / FRAME NAVIGATION is pinned to `127.0.0.1` by a
///     `WKNavigationDelegate` that cancels any navigation whose host is not
///     loopback. A link, redirect, or injected `window.location` therefore
///     cannot steer the embed off-machine or turn it into a general-purpose
///     browser. NOTE: `decidePolicyFor navigationAction` fires for navigations,
///     NOT for subresource fetches (images, scripts, XHR/fetch, CSS); on its
///     own it does not stop a page from pulling an off-machine subresource.
///   - SUBRESOURCE LOADS are blocked by a compiled `WKContentRuleList` installed
///     before the first load. The list blocks every URL, then re-admits ONLY
///     URLs whose `http(s)://` host is the `127.0.0.1` literal — keyed on the
///     SUBRESOURCE REQUEST's own URL via `url-filter`, NOT on the top-level
///     document's domain (see `loopbackOnlyRuleListJSON` for why the
///     document-keyed `unless-domain` form would be an inert no-op here). This
///     closes the off-machine subresource gap the navigation delegate cannot see
///     (e.g. a posture page that referenced `https://cdn.example/x.js` would have
///     that fetch blocked). The board is first-party loopback HTML, so this is
///     invisible in normal use and a hard stop for anything that is not.
///   - The posture read rides the local server's loopback auto-auth. NO bearer
///     token is ever placed in the URL or URL hash (a token in a URL leaks into
///     history, referers, and over-the-shoulder views). If a privileged read
///     ever needs a token in a later phase, it is injected as a request *header*
///     by the native app — never the URL — but this build's read does not need
///     one (posture read is loopback auto-auth, read-only).
///   - Server-down is presented as a NATIVE empty-state by the caller
///     (`ContentView`) using `checkServerHealth`; the web view is only created
///     once the server is confirmed reachable, so the operator never sees a raw
///     connection-refused browser page.
struct PostureWebView: NSViewRepresentable {
    /// The loopback URL of the posture board to load (always `127.0.0.1`).
    let url: URL

    /// The single host the embedded view is allowed to talk to. Any navigation
    /// or subresource fetch to a different host is cancelled / blocked.
    static let allowedHost = "127.0.0.1"

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        // No persistent data store: the embedded board holds no cross-launch
        // cookies/cache, and there is no token to persist anyway (loopback
        // auto-auth). Keeps the WebKit surface stateless.
        configuration.websiteDataStore = .nonPersistent()

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        // The embedded board is not a browser: disable back/forward swipe so a
        // gesture cannot walk navigation history off the pinned page.
        webView.allowsBackForwardNavigationGestures = false
        webView.setValue(false, forKey: "drawsBackground")

        // Install the subresource pin (blocks every off-loopback request) and
        // only then kick off the first load, so no off-machine subresource can
        // race ahead of the rule list. Claim `loadedURL` SYNCHRONOUSLY here (not
        // inside the async completion) so a `updateNSView` that fires while the
        // rule list is still compiling sees the load as already-claimed and does
        // not issue a second, duplicate load.
        guard Self.isLoopbackURL(url) else { return webView }
        context.coordinator.loadedURL = url
        installLoopbackSubresourcePin(on: webView) { [weak webView] in
            guard let webView else { return }
            webView.load(URLRequest(url: url))
        }
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        // CRITICAL (operator-navigation preservation): do NOT reload here on
        // every SwiftUI re-render. The arm-state / health poll re-evaluates this
        // view ~every 5s; reloading would snap the operator's in-board
        // navigation (drill-downs, filters, scroll) back to the home URL each
        // tick. We reload ONLY if the *target prop* `url` genuinely changes
        // (which it does not at runtime today). The operator's current location
        // inside the board — `webView.url` — is deliberately ignored here; it is
        // their navigation state, not a reload trigger.
        guard context.coordinator.loadedURL != url else { return }
        guard Self.isLoopbackURL(url) else { return }
        // A genuinely new target prop: re-pin subresources for it, then load.
        context.coordinator.loadedURL = url
        installLoopbackSubresourcePin(on: webView) { [weak webView] in
            guard let webView else { return }
            webView.load(URLRequest(url: url))
        }
    }

    /// Compile and install a content-rule list that BLOCKS every subresource
    /// request whose URL is not on `127.0.0.1`. This is the subresource half of
    /// the loopback pin (the navigation delegate is the navigation half). The
    /// completion runs ONLY on the success branch (after the rule list is
    /// installed). On the unexpected event of a compile failure we fail CLOSED:
    /// `completion` is intentionally NOT called, so `webView.load` is never
    /// issued and the web view stays blank rather than loading an unpinned page.
    /// (This leaves a blank `WKWebView`, not `ContentView`'s native server-down
    /// empty-state — that empty-state is driven by `serverStatus`, not by a
    /// rule-list compile result. The rule is static and should always compile, so
    /// this path is a defensive last resort, never a routine UI state.)
    private func installLoopbackSubresourcePin(
        on webView: WKWebView,
        then completion: @escaping () -> Void
    ) {
        WKContentRuleListStore.default().compileContentRuleList(
            forIdentifier: "sanctuary-loopback-only",
            encodedContentRuleList: Self.loopbackOnlyRuleListJSON
        ) { ruleList, error in
            if let ruleList, error == nil {
                webView.configuration.userContentController.add(ruleList)
                completion()
            } else {
                // Compile failed (should never happen for this static rule).
                // Fail CLOSED: do not load an unpinned page. `completion` is
                // deliberately NOT called here, so `webView.load` is never issued
                // and the web view is left blank. The navigation delegate would
                // still pin navigation, but without the subresource rule we refuse
                // to load at all rather than allow off-machine fetches.
            }
        }
    }

    /// Content-rule list JSON: block any request whose URL is NOT on the loopback
    /// literal, for every resource type.
    ///
    /// WHY NOT `unless-domain`: WebKit's `if-domain`/`unless-domain` are scoped on
    /// the TOP-LEVEL DOCUMENT's registrable domain (WebKit's
    /// `ContentExtensionsBackend` matches them against `mainDocumentURL`/`frameURL`,
    /// not the individual subresource request's URL). Because the embedded board's
    /// top-level document IS `127.0.0.1` (the navigation delegate guarantees it),
    /// an `unless-domain: ["127.0.0.1"]` would match the document on EVERY
    /// subresource and suppress the block for all of them — including off-machine
    /// ones. That makes the document-keyed form an inert no-op for this use. (A
    /// bare IP literal has no eTLD+1, so registrable-domain keying on it is also
    /// undefined.) The "not loopback" decision must therefore be expressed against
    /// the request URL itself, which only `url-filter` sees.
    ///
    /// HOW: WebKit's `url-filter` regex subset has no lookahead, so "block unless
    /// loopback" cannot be a single negated regex. Instead we use the canonical
    /// WebKit allowlist shape: (1) a broad `block` matching every URL, then (2) an
    /// `ignore-previous-rules` that re-admits ONLY URLs whose `http(s)://` host is
    /// exactly the loopback literal followed by a port or path delimiter. Rules
    /// apply in order, so the loopback exemption reverses the block for the board's
    /// own first-party subresources while every off-machine fetch stays blocked.
    /// The trailing `[:/]` (after the escaped literal, anchored at the URL start)
    /// is what keeps lookalikes blocked: `127.0.0.1.evil.test` has `.` next (not
    /// `:`/`/`) and `127.0.0.10` has `0` next, so neither is re-admitted.
    static let loopbackOnlyRuleListJSON = """
    [
      {
        "trigger": { "url-filter": ".*" },
        "action": { "type": "block" }
      },
      {
        "trigger": { "url-filter": "^https?://127\\\\.0\\\\.0\\\\.1[:/]" },
        "action": { "type": "ignore-previous-rules" }
      }
    ]
    """

    /// True iff `url` targets the loopback host over plain HTTP. Pinning to
    /// `127.0.0.1` (not `localhost`) avoids DNS-rebinding ambiguity entirely:
    /// `localhost` can resolve through a resolver, `127.0.0.1` is a literal.
    static func isLoopbackURL(_ url: URL?) -> Bool {
        guard let url else { return false }
        guard url.scheme == "http" else { return false }
        return url.host == allowedHost
    }

    /// Navigation delegate that hard-pins top-level/frame NAVIGATION to loopback.
    /// Any attempt to navigate to a non-`127.0.0.1` host is cancelled, so a link,
    /// redirect, or injected `window.location` cannot turn the embed into an
    /// off-machine browser. Subresource fetches are handled separately by the
    /// `WKContentRuleList` (this delegate callback does not fire for them).
    final class Coordinator: NSObject, WKNavigationDelegate {
        /// The `url` prop value that has actually been loaded into the web view.
        /// `updateNSView` compares against this so it reloads only when the
        /// target prop changes, never on routine SwiftUI re-renders (which would
        /// otherwise revert the operator's in-board navigation).
        var loadedURL: URL?

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            let target = navigationAction.request.url
            if PostureWebView.isLoopbackURL(target) {
                decisionHandler(.allow)
            } else {
                // Off-loopback (or non-http) navigation: cancel. The embedded
                // board never leaves 127.0.0.1.
                decisionHandler(.cancel)
            }
        }
    }
}
