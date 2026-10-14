/**
 * Mobile companion manifest colors come from the server tokens.
 *
 * Capability: the installed companion's splash background and status-bar
 * color are the light theme's --paper and --ink, the block the companion
 * paints with, read from the token values rather than hand-copied, and the
 * page's theme-color meta matches the manifest. A token change reaches an
 * installed app without a second edit.
 */

import { describe, it, expect } from "vitest";
import {
  MOBILE_COMPANION_WEBMANIFEST,
  renderMobileCompanionHTML,
} from "../../src/dashboard/mobile.js";
import { themeTokens } from "./console-style-helpers.js";

describe("mobile companion manifest colors", () => {
  const light = themeTokens().light;
  const manifest = JSON.parse(MOBILE_COMPANION_WEBMANIFEST) as { background_color: string; theme_color: string };

  it("background_color is the light theme's --paper and theme_color its --ink", () => {
    expect(manifest.background_color).toBe(light.paper);
    expect(manifest.theme_color).toBe(light.ink);
  });

  it("the page's theme-color meta is the same token as the manifest's theme_color", () => {
    const meta = renderMobileCompanionHTML().match(/<meta name="theme-color" content="([^"]+)">/);
    expect(meta?.[1]).toBe(light.ink);
    expect(meta?.[1]).toBe(manifest.theme_color);
  });
});
