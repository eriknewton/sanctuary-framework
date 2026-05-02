// Sanctuary Menubar frontend entry point.
// Wires together the fortress client, menubar tray, popover, notifications,
// and onboarding wizard. The Rust side handles tray icon creation, popover
// window lifecycle, and keychain. This module orchestrates state.

import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { FortressClient, type ClientConfig, type AuditEvent } from './api/client';
import { getMenubarBackend, getMacOSBackendForEvents } from './backends/menubar';
import { getNotificationBackend } from './backends/notification';
import { PopoverView } from './popover/popover';
import { OnboardingWizard } from './wizard/wizard';

const POLL_INTERVAL_MS = 2000;
const DEFAULT_FORTRESS_ENDPOINT = 'http://127.0.0.1:3501';

interface AppState {
  client: FortressClient | null;
  view: 'wizard' | 'popover';
  pollTimer: number | null;
  unsubscribeSse: (() => void) | null;
}

const state: AppState = {
  client: null,
  view: 'popover',
  pollTimer: null,
  unsubscribeSse: null,
};

async function loadConfig(): Promise<ClientConfig | null> {
  try {
    const cfg = (await invoke('config_load')) as ClientConfig | null;
    return cfg;
  } catch (err) {
    console.warn('config_load failed', err);
    return null;
  }
}

async function saveConfig(cfg: ClientConfig): Promise<void> {
  try {
    await invoke('config_save', { config: cfg });
  } catch (err) {
    console.warn('config_save failed', err);
  }
}

async function startPolling(): Promise<void> {
  if (state.pollTimer !== null) {
    clearInterval(state.pollTimer);
  }
  if (!state.client) return;
  const tick = async () => {
    if (!state.client) return;
    const snapshot = await state.client.fetchFleetSnapshot();
    const menubar = getMenubarBackend();
    await menubar.setBadge(snapshot.pending_tier1.length);
    await menubar.setIcon(snapshot.pending_tier1.length > 0 ? 'alert' : 'clear');

    if (state.view === 'popover') {
      const popover = new PopoverView('#root', {
        onOpenDashboard: () => openDashboard(snapshot.fortress_endpoint),
        onOpenSettings: () => startWizard(),
      });
      popover.render(snapshot);
    }
  };
  await tick();
  state.pollTimer = window.setInterval(tick, POLL_INTERVAL_MS);
}

function stopPolling(): void {
  if (state.pollTimer !== null) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  if (state.unsubscribeSse) {
    state.unsubscribeSse();
    state.unsubscribeSse = null;
  }
}

function subscribeTier1Events(): void {
  if (!state.client) return;
  if (state.unsubscribeSse) {
    state.unsubscribeSse();
  }
  state.unsubscribeSse = state.client.subscribeTier1Events(
    (event: AuditEvent) => {
      const notif = getNotificationBackend();
      const title = 'Sanctuary: action requires your approval';
      const body = event.operator_message ?? `${event.agent_id} is requesting an action that needs your approval.`;
      void notif.fire(title, body, () => {
        void getMenubarBackend().showPopover();
      });
    },
    (err) => {
      console.warn('SSE error', err);
    }
  );
}

function openDashboard(endpoint: string): void {
  void invoke('open_external', { url: endpoint });
}

function startWizard(): void {
  state.view = 'wizard';
  stopPolling();
  const wizard = new OnboardingWizard('#root', {
    onComplete: async (cfg) => {
      await saveConfig(cfg);
      state.client = new FortressClient(cfg);
      state.view = 'popover';
      await startPolling();
      subscribeTier1Events();
    },
    onCancel: () => {
      state.view = 'popover';
      void startPolling();
    },
  });
  wizard.start();
}

async function bootstrap(): Promise<void> {
  // Wire tray click → toggle popover.
  const menubar = getMenubarBackend();
  const macBackend = getMacOSBackendForEvents();
  if (macBackend) {
    await listen('tray-click', () => {
      macBackend.fireTrayClick();
    });
  }
  menubar.onTrayClick(() => {
    void menubar.showPopover();
  });

  // Load saved config or start onboarding.
  const cfg = await loadConfig();
  if (!cfg || !cfg.fortressEndpoint) {
    startWizard();
    return;
  }
  state.client = new FortressClient(cfg);
  state.view = 'popover';
  await startPolling();
  subscribeTier1Events();
}

void bootstrap().catch((err) => {
  console.error('bootstrap failed', err);
  // Render an inline error so first-run failures are visible to the operator.
  const root = document.getElementById('root');
  if (root) {
    root.innerHTML = `
      <div class="popover-container">
        <div class="popover-empty">
          <p><strong>Sanctuary Menubar failed to start.</strong></p>
          <p>${(err as Error).message}</p>
        </div>
      </div>
    `;
  }
});

// Re-export the default endpoint for documentation purposes.
export const _DEFAULT_FORTRESS_ENDPOINT = DEFAULT_FORTRESS_ENDPOINT;
