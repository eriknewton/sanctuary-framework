// Onboarding wizard skeleton. Structural shape complete. Copy and visual polish
// land in Sprint Piece 3. The wizard appears on first run when no fortress endpoint
// is configured. The operator can also reopen it from the popover footer.

import { invoke } from '@tauri-apps/api/core';
import { FortressClient, type ClientConfig } from '../api/client';
import { getNotificationBackend } from '../backends/notification';

export interface WizardDeps {
  onComplete: (config: ClientConfig) => Promise<void>;
  onCancel: () => void;
}

export type WizardStep = 'welcome' | 'endpoint' | 'auth' | 'notifications' | 'done';

export class OnboardingWizard {
  private root: HTMLElement;
  private step: WizardStep = 'welcome';
  private state: Partial<ClientConfig> = {};

  constructor(rootSelector: string, private deps: WizardDeps) {
    const el = document.querySelector(rootSelector) as HTMLElement | null;
    if (!el) throw new Error(`OnboardingWizard: root selector ${rootSelector} not found`);
    this.root = el;
  }

  start(): void {
    this.step = 'welcome';
    this.render();
  }

  private render(): void {
    this.root.innerHTML = '';
    const container = document.createElement('div');
    container.className = `wizard wizard-step-${this.step}`;
    switch (this.step) {
      case 'welcome':
        container.appendChild(this.renderWelcome());
        break;
      case 'endpoint':
        container.appendChild(this.renderEndpoint());
        break;
      case 'auth':
        container.appendChild(this.renderAuth());
        break;
      case 'notifications':
        container.appendChild(this.renderNotifications());
        break;
      case 'done':
        container.appendChild(this.renderDone());
        break;
    }
    this.root.appendChild(container);
  }

  private renderWelcome(): HTMLElement {
    const el = document.createElement('div');
    el.className = 'wizard-page';
    el.innerHTML = `
      <h1>Welcome to Sanctuary</h1>
      <p>Sanctuary keeps your AI agents on a leash you control. Let's set up your first fortress.</p>
      <p class="copy-stub">[Sprint Piece 3 fills in the full welcome copy + visual design.]</p>
      <div class="wizard-actions">
        <button class="btn btn-primary" data-action="next">Get started</button>
      </div>
    `;
    el.querySelector('[data-action="next"]')?.addEventListener('click', () => {
      this.step = 'endpoint';
      this.render();
    });
    return el;
  }

  private renderEndpoint(): HTMLElement {
    const el = document.createElement('div');
    el.className = 'wizard-page';
    el.innerHTML = `
      <h1>Where is your fortress?</h1>
      <p>Sanctuary needs to know where your local fortress is running. The default works for most operators.</p>
      <label class="field">
        <span>Fortress endpoint</span>
        <input type="url" id="endpoint-input" value="${this.state.fortressEndpoint ?? 'http://127.0.0.1:3501'}" />
      </label>
      <div class="test-result" id="endpoint-test-result"></div>
      <div class="wizard-actions">
        <button class="btn btn-link" data-action="back">Back</button>
        <button class="btn btn-secondary" data-action="test">Test connection</button>
        <button class="btn btn-primary" data-action="next">Continue</button>
      </div>
    `;
    el.querySelector('[data-action="back"]')?.addEventListener('click', () => {
      this.step = 'welcome';
      this.render();
    });
    el.querySelector('[data-action="test"]')?.addEventListener('click', async () => {
      const input = el.querySelector('#endpoint-input') as HTMLInputElement;
      const result = el.querySelector('#endpoint-test-result') as HTMLElement;
      result.textContent = 'Testing...';
      try {
        const probe = new FortressClient({ fortressEndpoint: input.value });
        const snap = await probe.fetchFleetSnapshot();
        if (snap.connection_status === 'disconnected') {
          result.textContent = 'Could not reach the fortress. Check the URL and that the fortress is running.';
          result.className = 'test-result fail';
        } else {
          result.textContent = `Connected. ${snap.agents.length} agent${snap.agents.length === 1 ? '' : 's'} wrapped.`;
          result.className = 'test-result ok';
        }
      } catch (err) {
        result.textContent = `Error: ${(err as Error).message}`;
        result.className = 'test-result fail';
      }
    });
    el.querySelector('[data-action="next"]')?.addEventListener('click', () => {
      const input = el.querySelector('#endpoint-input') as HTMLInputElement;
      this.state.fortressEndpoint = input.value;
      this.step = 'auth';
      this.render();
    });
    return el;
  }

  private renderAuth(): HTMLElement {
    const el = document.createElement('div');
    el.className = 'wizard-page';
    el.innerHTML = `
      <h1>Authentication (optional)</h1>
      <p>If your fortress requires an auth token, paste it here. Tokens are stored in your platform keychain.</p>
      <p class="copy-stub">[Sprint Piece 3 will detect whether the fortress requires auth and skip this step automatically when not needed.]</p>
      <label class="field">
        <span>Auth token</span>
        <input type="password" id="auth-token-input" value="${this.state.authToken ?? ''}" placeholder="Leave blank if not required" />
      </label>
      <div class="wizard-actions">
        <button class="btn btn-link" data-action="back">Back</button>
        <button class="btn btn-primary" data-action="next">Continue</button>
      </div>
    `;
    el.querySelector('[data-action="back"]')?.addEventListener('click', () => {
      this.step = 'endpoint';
      this.render();
    });
    el.querySelector('[data-action="next"]')?.addEventListener('click', async () => {
      const input = el.querySelector('#auth-token-input') as HTMLInputElement;
      const token = input.value.trim();
      if (token) {
        this.state.authToken = token;
        try {
          await invoke('keychain_set_token', { token });
        } catch (err) {
          console.warn('Failed to persist auth token to keychain', err);
        }
      }
      this.step = 'notifications';
      this.render();
    });
    return el;
  }

  private renderNotifications(): HTMLElement {
    const el = document.createElement('div');
    el.className = 'wizard-page';
    el.innerHTML = `
      <h1>Notifications</h1>
      <p>Sanctuary surfaces approval requests as OS notifications. We need permission to show them.</p>
      <div class="test-result" id="notif-result"></div>
      <div class="wizard-actions">
        <button class="btn btn-link" data-action="back">Back</button>
        <button class="btn btn-secondary" data-action="request">Request permission</button>
        <button class="btn btn-primary" data-action="next">Continue</button>
      </div>
    `;
    el.querySelector('[data-action="back"]')?.addEventListener('click', () => {
      this.step = 'auth';
      this.render();
    });
    el.querySelector('[data-action="request"]')?.addEventListener('click', async () => {
      const result = el.querySelector('#notif-result') as HTMLElement;
      try {
        const granted = await getNotificationBackend().requestPermission();
        result.textContent = granted ? 'Permission granted.' : 'Permission denied. You can enable it later in System Settings.';
        result.className = `test-result ${granted ? 'ok' : 'fail'}`;
      } catch (err) {
        result.textContent = `Error: ${(err as Error).message}`;
        result.className = 'test-result fail';
      }
    });
    el.querySelector('[data-action="next"]')?.addEventListener('click', () => {
      this.step = 'done';
      this.render();
    });
    return el;
  }

  private renderDone(): HTMLElement {
    const el = document.createElement('div');
    el.className = 'wizard-page';
    el.innerHTML = `
      <h1>You're set up</h1>
      <p>Sanctuary is now watching your fortress. The menubar icon shows pending approvals at a glance.</p>
      <p class="copy-stub">[Sprint Piece 3 fills in the full done-page copy + a quick tour of the popover.]</p>
      <div class="wizard-actions">
        <button class="btn btn-primary" data-action="finish">Done</button>
      </div>
    `;
    el.querySelector('[data-action="finish"]')?.addEventListener('click', async () => {
      if (!this.state.fortressEndpoint) {
        this.deps.onCancel();
        return;
      }
      await this.deps.onComplete({
        fortressEndpoint: this.state.fortressEndpoint,
        authToken: this.state.authToken,
      });
    });
    return el;
  }
}
