/**
 * Sanctuary v1.1 Dashboard — Public Surface
 *
 * Re-exports the v1.1 dashboard module. Consumers (server bootstrap, tests,
 * future operator-cloud variants) import from this barrel.
 */

export {
  renderDashboardV11Html,
  type DashboardV11HtmlOptions,
} from "./html.js";
export { handleDashboardV11Route, type DashboardV11RouteDeps } from "./routes.js";
export {
  renderTemplate,
  listRegisteredTemplateIds,
  type TemplateRenderContext,
  type TemplateRenderer,
} from "./templates.js";
export {
  STATUS_MAPPING,
  STATUS_REASON_LABELS,
  TIER1_BUTTON_COPY,
  resolveStatus,
  type Tier1ButtonState,
  type Tier1ButtonCopy,
  type UiStatusEntry,
  type UiPresenceGlyph,
} from "./status-mapping.js";
export {
  extractStreamEventId,
  type HubV11StreamEvent,
  type HubInboxStreamEvent,
  type HubAgentStatusStreamEvent,
  type HubActivityStreamEvent,
} from "./sse-events.js";
export { getClientScript } from "./client.js";
