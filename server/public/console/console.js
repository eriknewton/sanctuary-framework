/**
 * Sanctuary Operator Console v1.0 -- Client JS
 *
 * Vanilla JS router + view renderers + API client + SSE subscriber.
 * No framework. No external CDN imports. Zero external resource fetches.
 *
 * WP-MVP-2: Key 4 Console.
 *
 * Chat view says "forward-secret group chat" or "AES-256-GCM per-epoch",
 * NOT "MLS" (per Scope Lock amendment, v1.1 dead-claims watch).
 */

/* global document, window, fetch, EventSource, FormData, JSON, alert, confirm */

(function () {
  "use strict";

  // ── API paths ──────────────────────────────────────────────────────
  var API = {
    HEADER_BADGE: "/api/console/header/badge",
    FORTRESS_MODE: "/api/console/fortress/mode",
    FORTRESS_TRANSITION: "/api/console/fortress/transition",
    AGENT_LIST: "/api/console/agents",
    AGENT_BADGE: "/api/console/agents/badge",
    POLICY_TEMPLATES: "/api/console/policy/templates",
    POLICY_COMPILE: "/api/console/policy/compile",
    CHAT_GROUPS: "/api/console/chat/groups",
    CHAT_MESSAGES: "/api/console/chat/messages",
    CHAT_SEND: "/api/console/chat/send",
    CHAT_PRESENCE: "/api/console/chat/presence",
    RECOVERY_STATUS: "/api/console/recovery/status",
    RECOVERY_GUARDIANS: "/api/console/recovery/guardians",
    RECOVERY_DMSWITCH: "/api/console/recovery/dmswitch",
    AUDIT_EVENTS: "/api/console/audit/events",
    EVENTS: "/api/console/events",
    TEMPLATES_LIST: "/api/templates",
    TEMPLATE_DETAIL: "/api/templates/",
    TEMPLATE_INIT: "/api/templates/",
  };

  var TIER_LABELS = {
    tier_1_private: "Tier 1: Private",
    tier_2_federated: "Tier 2: Federated",
    tier_3_interop: "Tier 3: Interop",
  };

  var BADGE_LABELS = {
    green: "Walls sound",
    yellow: "Walls watch",
    red: "Walls breached",
    offline: "No signal",
    local_only: "Local mode",
  };

  // ── Helpers ────────────────────────────────────────────────────────

  function qs(sel, root) { return (root || document).querySelector(sel); }
  function qsa(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

  function escapeHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function badgeClass(state) {
    if (state === "local_only") return "badge badge-local";
    return "badge badge-" + (state || "offline");
  }

  function badgeLabel(state) {
    return BADGE_LABELS[state] || state || "Unknown";
  }

  async function apiGet(url) {
    var resp = await fetch(url, { credentials: "include" });
    return resp.json();
  }

  async function apiPost(url, body) {
    var resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "include",
    });
    return resp.json();
  }

  // ── View Routing ───────────────────────────────────────────────────

  var currentView = "fortress";

  function updateNav() {
    var hash = (window.location.hash || "#fortress").slice(1);
    currentView = hash;
    qsa(".nav-item").forEach(function (el) {
      if (el.dataset.view === hash) el.classList.add("active");
      else el.classList.remove("active");
    });
    qsa(".view-panel").forEach(function (s) {
      s.style.display = s.dataset.view === hash ? "" : "none";
    });
    loadView(hash);
  }

  window.addEventListener("hashchange", updateNav);

  // ── Header ─────────────────────────────────────────────────────────

  async function loadHeader() {
    try {
      var res = await apiGet(API.HEADER_BADGE);
      if (res.ok && res.data) {
        var d = res.data;
        var badge = qs("#header-global-badge");
        badge.className = badgeClass(d.global_badge.state);
        badge.textContent = badgeLabel(d.global_badge.state);
        badge.title = d.global_badge.label || "";
        qs("#header-fortress-tier").textContent = d.fortress_tier_label || TIER_LABELS[d.fortress_tier] || d.fortress_tier;
        qs("#header-peer-count").textContent = (d.federation_peer_count || 0) + " peers";
      }
    } catch (e) { /* offline fallback */ }
  }

  // ── Fortress View ──────────────────────────────────────────────────

  async function loadFortressView() {
    var res = await apiGet(API.FORTRESS_MODE);
    if (!res.ok) return;
    var d = res.data;
    qs("#fortress-tier").textContent = TIER_LABELS[d.current_tier] || d.current_tier;
    qs("#fortress-capability-bits").textContent = String(d.capability_bits);
    qs("#fortress-last-transition").textContent = d.last_transition_at || "Never";

    // Transition buttons
    var bar = qs("#fortress-transition-actions");
    bar.innerHTML = "";
    (d.legal_targets || []).forEach(function (target) {
      var btn = document.createElement("button");
      btn.className = "btn-primary";
      btn.textContent = "Transition to " + (TIER_LABELS[target] || target);
      btn.addEventListener("click", function () {
        var reason = window.prompt("Reason for transition:", "");
        if (reason === null) return;
        apiPost(API.FORTRESS_TRANSITION, { target_tier: target, reason: reason })
          .then(function (r) {
            if (r.ok) { loadFortressView(); loadHeader(); }
            else alert("Transition failed: " + (r.detail || r.error));
          });
      });
      bar.appendChild(btn);
    });

    // History table
    var tbody = qs("#fortress-history tbody");
    tbody.innerHTML = "";
    (d.transitions_history || []).forEach(function (h) {
      var tr = document.createElement("tr");
      tr.innerHTML = "<td>" + escapeHtml(TIER_LABELS[h.from_tier] || h.from_tier) + "</td>"
        + "<td>" + escapeHtml(TIER_LABELS[h.to_tier] || h.to_tier) + "</td>"
        + "<td>" + escapeHtml(h.reason) + "</td>"
        + "<td>" + escapeHtml(h.transitioned_at) + "</td>";
      tbody.appendChild(tr);
    });
  }

  // ── Agent Roster View ──────────────────────────────────────────────

  async function loadAgentRosterView() {
    var res = await apiGet(API.AGENT_LIST);
    if (!res.ok) return;
    var d = res.data;
    var tbody = qs("#agent-table tbody");
    tbody.innerHTML = "";
    var empty = qs("#agent-empty");

    if (!d.agents || d.agents.length === 0) {
      empty.style.display = "";
      return;
    }
    empty.style.display = "none";

    d.agents.forEach(function (a) {
      var tr = document.createElement("tr");
      tr.innerHTML = "<td>" + escapeHtml(a.agent_id) + "</td>"
        + "<td>" + escapeHtml(a.tier) + "</td>"
        + "<td>" + escapeHtml(a.harness_id) + "</td>"
        + "<td>" + escapeHtml(a.model_provider + "/" + a.model_id) + "</td>"
        + "<td>v" + a.policy_version + "</td>"
        + '<td><span class="' + badgeClass(a.badge.state) + '">' + badgeLabel(a.badge.state) + "</span></td>";
      tbody.appendChild(tr);
    });
  }

  // ── Policy Editor View ─────────────────────────────────────────────

  async function loadPolicyEditorView() {
    var res = await apiGet(API.POLICY_TEMPLATES);
    if (!res.ok) return;
    var templates = res.data.templates || [];
    var select = qs("#policy-template-select");
    select.innerHTML = "";
    templates.forEach(function (t) {
      var opt = document.createElement("option");
      opt.value = t.id;
      opt.textContent = t.label;
      select.appendChild(opt);
    });

    var list = qs("#policy-template-list");
    list.innerHTML = "";
    templates.forEach(function (t) {
      var li = document.createElement("li");
      li.innerHTML = "<strong>" + escapeHtml(t.label) + "</strong> (<code>" + escapeHtml(t.id) + "</code>): " + escapeHtml(t.description);
      list.appendChild(li);
    });
  }

  // ── Chat View ──────────────────────────────────────────────────────

  async function loadChatView() {
    var groupRes = await apiGet(API.CHAT_GROUPS);
    if (groupRes.ok && groupRes.data) {
      var ul = qs("#chat-groups");
      ul.innerHTML = "";
      (groupRes.data.groups || []).forEach(function (g) {
        var li = document.createElement("li");
        li.textContent = g.group_id.slice(0, 12) + "... (" + g.member_count + " members)";
        li.style.cursor = "pointer";
        li.addEventListener("click", function () { loadChatMessages(g.group_id); });
        ul.appendChild(li);
      });
    }

    var presRes = await apiGet(API.CHAT_PRESENCE);
    if (presRes.ok && presRes.data) {
      var pl = qs("#chat-presence");
      pl.innerHTML = "";
      (presRes.data.presence || []).forEach(function (p) {
        var li = document.createElement("li");
        li.className = "presence-" + p.state;
        li.textContent = p.member_id.slice(0, 12) + "... " + p.state;
        pl.appendChild(li);
      });
    }
  }

  var activeChatGroup = null;

  async function loadChatMessages(groupId) {
    activeChatGroup = groupId;
    var res = await apiGet(API.CHAT_MESSAGES + "?group_id=" + encodeURIComponent(groupId) + "&limit=50");
    var container = qs("#chat-messages");
    container.innerHTML = "";
    if (res.ok && res.data && res.data.messages) {
      res.data.messages.forEach(function (m) {
        var div = document.createElement("div");
        div.className = "chat-msg";
        div.innerHTML = '<span class="chat-msg-sender">' + escapeHtml(m.sender_id) + '</span>'
          + '<span class="chat-msg-time">' + escapeHtml(m.sent_at) + '</span>'
          + "<div>" + escapeHtml(m.content) + "</div>";
        container.appendChild(div);
      });
    }
    qs("#chat-send-form").style.display = "flex";
  }

  // ── Recovery View ──────────────────────────────────────────────────

  async function loadRecoveryView() {
    var res = await apiGet(API.RECOVERY_STATUS);
    if (!res.ok) return;
    var d = res.data;
    qs("#recovery-threshold").textContent = d.threshold_m + " of " + d.threshold_n;
    qs("#recovery-dmswitch-window").textContent = d.dmswitch.window_label;
    qs("#recovery-estate-planning").textContent = d.dmswitch.estate_planning_enabled ? "Enabled" : "Disabled";
    qs("#recovery-last-activity").textContent = d.dmswitch.last_activity_at || "No activity recorded";

    // Guardian table
    var tbody = qs("#guardian-table tbody");
    tbody.innerHTML = "";
    (d.roster.guardians || []).forEach(function (g) {
      var tr = document.createElement("tr");
      tr.innerHTML = "<td>" + escapeHtml(g.guardian_id) + "</td>"
        + "<td><code>" + escapeHtml((g.guardian_pubkey || "").slice(0, 16)) + "...</code></td>"
        + "<td>" + escapeHtml(g.enrolled_at || "unknown") + "</td>";
      tbody.appendChild(tr);
    });

    // Cascades
    var cascadeDiv = qs("#recovery-cascades");
    if (d.active_cascades && d.active_cascades.length > 0) {
      cascadeDiv.innerHTML = "";
      d.active_cascades.forEach(function (c) {
        var cls = "cascade-card";
        if (c.state === "completed") cls += " cascade-card-completed";
        if (c.state === "failed") cls += " cascade-card-failed";
        var div = document.createElement("div");
        div.className = cls;
        div.innerHTML = "<strong>" + escapeHtml(c.action) + "</strong> "
          + escapeHtml(c.state) + " (M=" + c.threshold_m + ", approved: " + (c.approvals || []).length + ")"
          + "<br/>Initiated: " + escapeHtml(c.initiated_at);
        cascadeDiv.appendChild(div);
      });
    } else {
      cascadeDiv.innerHTML = '<p class="empty-state">No active recovery cascades.</p>';
    }
  }

  // ── Audit Log View ─────────────────────────────────────────────────

  async function loadAuditLogView() {
    var filterSelect = qs("#audit-filter");
    var selected = Array.from(filterSelect.selectedOptions).map(function (o) { return o.value; });
    var url = API.AUDIT_EVENTS;
    if (selected.length > 0) url += "?filters=" + encodeURIComponent(selected.join(","));

    var res = await apiGet(url);
    if (!res.ok) return;
    var d = res.data;
    var tbody = qs("#audit-table tbody");
    tbody.innerHTML = "";
    (d.events || []).forEach(function (e) {
      var tr = document.createElement("tr");
      tr.style.cursor = "pointer";
      tr.innerHTML = "<td><code>" + escapeHtml((e.event_id || "").slice(0, 12)) + "...</code></td>"
        + "<td>" + escapeHtml(e.event_type) + "</td>"
        + "<td><code>" + escapeHtml((e.emitter_node || "").slice(0, 12)) + "...</code></td>"
        + "<td>" + escapeHtml(e.emitted_at) + "</td>"
        + "<td>" + escapeHtml(e.payload_preview) + "</td>";
      tr.addEventListener("click", function () {
        qs("#envelope-json").textContent = e.envelope_json || "{}";
        qs("#envelope-dialog").showModal();
      });
      tbody.appendChild(tr);
    });
  }

  // ── Template Picker + Scaffold Flow ─────────────────────────────────

  var scaffoldTemplateName = null;

  async function openTemplatePicker() {
    var dialog = qs("#template-picker-dialog");
    var step1 = qs("#template-picker-step-1");
    var step2 = qs("#template-picker-step-2");
    var cardList = qs("#template-card-list");
    var resultBox = qs("#scaffold-result");

    // Reset to step 1
    step1.style.display = "";
    step2.style.display = "none";
    resultBox.style.display = "none";
    cardList.innerHTML = '<p class="empty-state">Loading templates...</p>';

    dialog.showModal();

    try {
      var res = await apiGet(API.TEMPLATES_LIST);
      var templates = (res && res.templates) || [];
      cardList.innerHTML = "";
      templates.forEach(function (t) {
        var card = document.createElement("div");
        card.className = "template-card";
        card.innerHTML = "<strong>" + escapeHtml(t.metadata.name) + "</strong>"
          + "<br/><small>" + escapeHtml(t.metadata.description) + "</small>"
          + "<br/><span class='badge badge-local'>" + escapeHtml(t.metadata.channel) + "</span>"
          + " <span class='badge badge-local'>Tier " + escapeHtml(t.metadata.tier) + "</span>";
        card.style.cursor = "pointer";
        card.addEventListener("click", function () {
          selectTemplate(t.metadata.name);
        });
        cardList.appendChild(card);
      });
    } catch (e) {
      cardList.innerHTML = '<p class="empty-state">Failed to load templates.</p>';
    }
  }

  async function selectTemplate(name) {
    scaffoldTemplateName = name;
    var step1 = qs("#template-picker-step-1");
    var step2 = qs("#template-picker-step-2");
    var resultBox = qs("#scaffold-result");
    resultBox.style.display = "none";

    qs("#scaffold-template-title").textContent = "Scaffold: " + name;
    step1.style.display = "none";
    step2.style.display = "";

    // Fetch template details for policy preview + egress
    try {
      var res = await apiGet(API.TEMPLATE_DETAIL + encodeURIComponent(name));
      if (res && res.metadata) {
        var preview = qs("#scaffold-policy-preview");
        preview.textContent = "Channel: " + res.metadata.channel
          + "\nTier: " + res.metadata.tier
          + "\n\n" + (res.onboarding || "").slice(0, 500);

        // Pre-select model provider based on template
        var provSelect = qs('#scaffold-form select[name="model_provider"]');
        if (name === "x-miner") provSelect.value = "xai";
        else if (name === "github-miner") provSelect.value = "anthropic";
        else provSelect.value = "anthropic";
      }
    } catch (e) { /* proceed with defaults */ }

    // Reset form
    qs('#scaffold-form input[name="agent_name"]').value = "";
    qs('#scaffold-form input[name="extra_egress"]').value = "";
  }

  async function handleScaffoldSubmit(ev) {
    ev.preventDefault();
    if (!scaffoldTemplateName) return;
    var fd = new FormData(qs("#scaffold-form"));
    var agentName = fd.get("agent_name");
    var modelProvider = fd.get("model_provider");
    var extraEgress = fd.get("extra_egress");

    var body = {
      agent_name: agentName,
      model_provider: modelProvider,
    };
    if (extraEgress) {
      body.overrides = { egress_allow: [extraEgress] };
    }

    var resultBox = qs("#scaffold-result");
    try {
      var res = await apiPost(
        API.TEMPLATE_INIT + encodeURIComponent(scaffoldTemplateName) + "/init",
        body
      );
      if (res.agent_id) {
        resultBox.style.display = "";
        resultBox.textContent = "Agent \"" + res.agent_id + "\" scaffolded successfully. "
          + "Policy v" + res.policy_version + " pinned. "
          + "Event: " + res.signed_event_id;
        // Refresh agent roster after scaffold
        loadAgentRosterView();
      } else {
        resultBox.style.display = "";
        resultBox.textContent = "Error: " + (res.message || res.error || "Unknown error");
      }
    } catch (e) {
      resultBox.style.display = "";
      resultBox.textContent = "Error: " + (e.message || "Request failed");
    }
  }

  // ── View Router ────────────────────────────────────────────────────

  function loadView(view) {
    switch (view) {
      case "fortress": loadFortressView(); break;
      case "agent_roster": loadAgentRosterView(); break;
      case "policy_editor": loadPolicyEditorView(); break;
      case "chat": loadChatView(); break;
      case "recovery": loadRecoveryView(); break;
      case "audit_log": loadAuditLogView(); break;
    }
  }

  // ── Form Handlers ──────────────────────────────────────────────────

  document.addEventListener("DOMContentLoaded", function () {
    // Policy form
    var pf = qs("#policy-form");
    if (pf) pf.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var fd = new FormData(pf);
      var scopeStr = fd.get("scope_json");
      var scope;
      if (scopeStr) {
        try { scope = JSON.parse(scopeStr); } catch (_) {
          alert("Scope must be valid JSON or empty."); return;
        }
      }
      apiPost(API.POLICY_COMPILE, {
        agent_id: fd.get("agent_id"),
        counterparty: fd.get("counterparty"),
        channel_template_id: fd.get("channel_template_id"),
        scope: scope,
      }).then(function (r) {
        var box = qs("#policy-result");
        if (r.ok) {
          box.style.display = "";
          box.textContent = "Policy v" + r.data.policy_version + " pinned. " + r.data.source_english;
        } else {
          box.style.display = "";
          box.textContent = "Error: " + (r.detail || r.error);
        }
      });
    });

    // Chat send form
    var cf = qs("#chat-send-form");
    if (cf) cf.addEventListener("submit", function (ev) {
      ev.preventDefault();
      if (!activeChatGroup) return;
      var fd = new FormData(cf);
      apiPost(API.CHAT_SEND, {
        group_id: activeChatGroup,
        content: fd.get("content"),
      }).then(function () {
        cf.reset();
        loadChatMessages(activeChatGroup);
      });
    });

    // Audit refresh
    var ar = qs("#audit-refresh");
    if (ar) ar.addEventListener("click", loadAuditLogView);

    // Envelope dialog close
    var ec = qs("#envelope-close");
    if (ec) ec.addEventListener("click", function () {
      qs("#envelope-dialog").close();
    });

    // Template picker: "Add Agent" button
    var addAgentBtn = qs("#add-agent-btn");
    if (addAgentBtn) addAgentBtn.addEventListener("click", openTemplatePicker);

    // Template picker: close button
    var tpc = qs("#template-picker-close");
    if (tpc) tpc.addEventListener("click", function () {
      qs("#template-picker-dialog").close();
    });

    // Template picker: back button
    var sb = qs("#scaffold-back");
    if (sb) sb.addEventListener("click", function () {
      qs("#template-picker-step-1").style.display = "";
      qs("#template-picker-step-2").style.display = "none";
    });

    // Template picker: scaffold form submit
    var sf = qs("#scaffold-form");
    if (sf) sf.addEventListener("submit", handleScaffoldSubmit);

    // ── SSE ─────────────────────────────────────────────────────────
    try {
      var es = new EventSource(API.EVENTS);
      es.addEventListener("hydrate", function (e) {
        try {
          var data = JSON.parse(e.data);
          if (data.header) {
            var h = data.header;
            var badge = qs("#header-global-badge");
            badge.className = badgeClass(h.global_badge.state);
            badge.textContent = badgeLabel(h.global_badge.state);
            qs("#header-fortress-tier").textContent = h.fortress_tier_label || h.fortress_tier;
            qs("#header-peer-count").textContent = (h.federation_peer_count || 0) + " peers";
          }
        } catch (_) {}
      });
      es.addEventListener("message", function (e) {
        try {
          var evt = JSON.parse(e.data);
          if (evt.kind === "header") loadHeader();
          if (evt.kind === currentView) loadView(currentView);
          if (evt.kind === "audit_event" && currentView === "audit_log") loadAuditLogView();
        } catch (_) {}
      });
      es.addEventListener("error", function () { /* browser auto-retries */ });
    } catch (_) { /* older runtime */ }

    // Init
    loadHeader();
    updateNav();
  });

})();
