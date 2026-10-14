import { test, expect } from "@playwright/test";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";

const STORAGE_KEY = "sanctuary_fleet_machines";

async function startFleetSwitcher(): Promise<{ url: string; stop: () => Promise<void> }> {
  let channel: DashboardApprovalChannel | null = null;
  let port = 0;
  await bindWithRetry(async () => {
    port = randomTestPort();
    channel = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 2,
    });
    await channel.start();
  });

  return {
    url: `http://127.0.0.1:${port}`,
    stop: async () => {
      await channel?.stop();
    },
  };
}

test("fleet switcher renders saved cards as text and keeps unsupported addresses view-only", async ({
  page,
}) => {
  const fleet = await startFleetSwitcher();
  const entries = [
    {
      name: "O'Brien <b>bold</b>",
      url: `${fleet.url}/named`,
    },
    {
      name: "FTP entry",
      url: "ftp://example.test/",
    },
    {
      name: "Unicode host",
      url: "http://例え.test:3501",
    },
    {
      name: "Loopback",
      url: fleet.url,
    },
  ];

  try {
    await page.route("**/api/health", async (route) => {
      await route.fulfill({
        status: 200,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ok: true }),
      });
    });
    await page.addInitScript(
      ({ key, value }) => {
        localStorage.setItem(key, JSON.stringify(value));
      },
      { key: STORAGE_KEY, value: entries },
    );

    await page.goto(`${fleet.url}/fleet`);

    const list = page.locator("#machine-list");
    const cards = list.locator(".machine-card");
    await expect(cards).toHaveCount(4);
    await expect(list.locator("b")).toHaveCount(0);
    await expect(cards.nth(0).locator(".name")).toHaveText("O'Brien <b>bold</b>");

    await expect(cards.nth(0).locator("a.btn-open")).toHaveAttribute(
      "href",
      entries[0].url,
    );
    await expect(cards.nth(1).locator("a.btn-open")).toHaveCount(0);
    await expect(cards.nth(1).locator(".status-label")).toHaveText("Not checked");
    await expect(cards.nth(2).locator("a.btn-open")).toHaveAttribute(
      "href",
      entries[2].url,
    );
    await expect(cards.nth(3).locator("a.btn-open")).toHaveAttribute(
      "href",
      entries[3].url,
    );

    for (const [index, entry] of entries.entries()) {
      await page.evaluate(
        ({ key, value }) => {
          localStorage.setItem(key, JSON.stringify(value));
          (globalThis as unknown as { render: () => void }).render();
        },
        { key: STORAGE_KEY, value: entries },
      );
      await page.locator(".machine-card").nth(index).locator(".btn-remove").click();
      const stored = await page.evaluate((key) => {
        return JSON.parse(localStorage.getItem(key) || "[]") as Array<{ url: string }>;
      }, STORAGE_KEY);
      expect(stored.some((saved) => saved.url === entry.url)).toBe(false);
      for (const other of entries.filter((candidate) => candidate.url !== entry.url)) {
        expect(stored.some((saved) => saved.url === other.url)).toBe(true);
      }
    }
  } finally {
    await fleet.stop();
  }
});

test("fleet switcher add form accepts only http and https addresses", async ({ page }) => {
  const fleet = await startFleetSwitcher();
  try {
    await page.goto(`${fleet.url}/fleet`);

    await page.locator("#machine-name").fill("FTP entry");
    await page.locator("#machine-url").fill("ftp://example.test");
    await page.getByRole("button", { name: "Add Machine" }).click();

    await expect(page.locator("#form-hint")).toHaveText(
      "Enter an http or https address.",
    );
    await expect(page.locator("#machine-url")).toHaveClass(/invalid/);
    const stored = await page.evaluate((key) => {
      return JSON.parse(localStorage.getItem(key) || "[]") as Array<{ url: string }>;
    }, STORAGE_KEY);
    expect(stored.some((entry) => entry.url === "ftp://example.test")).toBe(false);
  } finally {
    await fleet.stop();
  }
});

test("fleet switcher add form preserves stored entries outside the visible list", async ({
  page,
}) => {
  const fleet = await startFleetSwitcher();
  const validEntry = { name: "Visible", url: `${fleet.url}/visible` };
  const rawEntries = [null, { name: 1 }, validEntry];
  try {
    await page.addInitScript(
      ({ key, value }) => {
        localStorage.setItem(key, JSON.stringify(value));
      },
      { key: STORAGE_KEY, value: rawEntries },
    );
    await page.goto(`${fleet.url}/fleet`);

    await page.locator("#machine-name").fill("Added");
    await page.locator("#machine-url").fill(`${fleet.url}/added`);
    await page.getByRole("button", { name: "Add Machine" }).click();

    const stored = await page.evaluate((key) => {
      return JSON.parse(localStorage.getItem(key) || "[]") as unknown[];
    }, STORAGE_KEY);
    expect(stored).toEqual(
      expect.arrayContaining([
        null,
        { name: 1 },
        expect.objectContaining(validEntry),
        expect.objectContaining({ name: "Added", url: `${fleet.url}/added` }),
      ]),
    );
  } finally {
    await fleet.stop();
  }
});

test("fleet switcher leaves a non-list storage root unchanged on load", async ({ page }) => {
  const fleet = await startFleetSwitcher();
  try {
    await page.addInitScript((key) => {
      localStorage.setItem(key, "{}");
    }, STORAGE_KEY);

    await page.goto(`${fleet.url}/fleet`);

    const stored = await page.evaluate((key) => {
      return localStorage.getItem(key);
    }, STORAGE_KEY);
    expect(stored).toBe("{}");
  } finally {
    await fleet.stop();
  }
});

test("fleet switcher removes the selected saved address with an apostrophe", async ({
  page,
}) => {
  const fleet = await startFleetSwitcher();
  const apostropheEntry = { name: "OBrien", url: `${fleet.url}/o'brien` };
  const otherEntry = { name: "Other", url: `${fleet.url}/other` };
  try {
    await page.addInitScript(
      ({ key, value }) => {
        localStorage.setItem(key, JSON.stringify(value));
      },
      { key: STORAGE_KEY, value: [apostropheEntry, otherEntry] },
    );

    await page.goto(`${fleet.url}/fleet`);
    await page
      .locator(".machine-card", { hasText: apostropheEntry.url })
      .locator(".btn-remove")
      .click();

    const stored = await page.evaluate((key) => {
      return JSON.parse(localStorage.getItem(key) || "[]") as Array<{ url: string }>;
    }, STORAGE_KEY);
    expect(stored.some((entry) => entry.url === apostropheEntry.url)).toBe(false);
    expect(stored.some((entry) => entry.url === otherEntry.url)).toBe(true);
  } finally {
    await fleet.stop();
  }
});

test("fleet switcher Open Console links stay in the current tab", async ({ page }) => {
  const fleet = await startFleetSwitcher();
  const entry = { name: "Loopback", url: fleet.url };
  try {
    await page.addInitScript(
      ({ key, value }) => {
        localStorage.setItem(key, JSON.stringify(value));
      },
      { key: STORAGE_KEY, value: [entry] },
    );

    await page.goto(`${fleet.url}/fleet`);

    await expect(page.locator("a.btn-open").first()).not.toHaveAttribute("target", /.*/);
  } finally {
    await fleet.stop();
  }
});
