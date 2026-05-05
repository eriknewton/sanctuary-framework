// Onboarding wizard. Sprint Piece 1 (PR #104) shipped the structural
// skeleton: 5 steps, state-machine plumbing, fortress-endpoint probe,
// auth-token keychain persistence, notification-permission request.
//
// Sprint Piece 2 PR 5 polishes the visuals. The state machine is
// preserved verbatim. Visual primitives are translated from
// server/docs/design-refs/sprint-piece-2/surface-onboarding.jsx and
// surfaces.css Onboarding block. State-specific design surfaces
// (substrate selection, success receipt, next-CTA grid) are Sprint
// Piece 3 territory.
//
// The wizard appears on first run when no fortress endpoint is
// configured. The operator can also reopen it from the popover footer.

import { invoke } from '@tauri-apps/api/core';
import { FortressClient, type ClientConfig } from '../api/client';
import { getNotificationBackend } from '../backends/notification';

export interface WizardDeps {
  onComplete: (config: ClientConfig) => Promise<void>;
  onCancel: () => void;
}

export type WizardStep = 'welcome' | 'endpoint' | 'auth' | 'notifications' | 'done';

const STEP_ORDER: WizardStep[] = ['welcome', 'endpoint', 'auth', 'notifications', 'done'];
const TOTAL_STEPS = STEP_ORDER.length;

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
    const stage = document.createElement('div');
    stage.className = `onb-stage wizard-step-${this.step}`;
    const card = document.createElement('div');
    card.className = 'onb-card wizard';
    switch (this.step) {
      case 'welcome':
        card.appendChild(this.renderWelcome());
        break;
      case 'endpoint':
        card.appendChild(this.renderEndpoint());
        break;
      case 'auth':
        card.appendChild(this.renderAuth());
        break;
      case 'notifications':
        card.appendChild(this.renderNotifications());
        break;
      case 'done':
        card.appendChild(this.renderDone());
        break;
    }
    stage.appendChild(card);
    this.root.appendChild(stage);
  }

  private renderProgress(): string {
    const idx = STEP_ORDER.indexOf(this.step);
    const dots = STEP_ORDER.map((_s, i) => {
      const cls = i < idx ? 'done' : i === idx ? 'active' : '';
      return `<span class="${cls}"></span>`;
    }).join('');
    return `
      <div class="onb-progress">
        <span>Step ${idx + 1} of ${TOTAL_STEPS}</span>
        <span class="step-dots">${dots}</span>
      </div>
    `;
  }

  private renderWelcome(): HTMLElement {
    const el = document.createElement('div');
    el.className = 'wizard-page';
    el.innerHTML = `
      ${this.renderProgress()}
      <h1>Welcome to Sanctuary.</h1>
      <p class="lede">Sanctuary watches the actions your AI agents take and surfaces them for your approval. Five short steps to point this menubar at your fortress.</p>
      <div class="onb-actions">
        <button class="btn btn-link" data-action="skip">Skip setup</button>
        <button class="btn btn-primary" data-action="next">Get started</button>
        <span class="key">${enterKeyHint('to start')}</span>
      </div>
    `;
    el.querySelector('[data-action="skip"]')?.addEventListener('click', () => {
      this.deps.onCancel();
    });
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
      ${this.renderProgress()}
      <h1>Where is your fortress.</h1>
      <p class="lede">Sanctuary needs the address of your local fortress. The default works for most operators.</p>
      <label class="field">
        <span>Fortress endpoint</span>
        <input type="url" id="endpoint-input" value="${this.state.fortressEndpoint ?? 'http://127.0.0.1:3501'}" />
      </label>
      <div class="test-result" id="endpoint-test-result"></div>
      <div class="onb-actions">
        <button class="btn btn-link" data-action="back">Back</button>
        <button class="btn btn-secondary" data-action="test">Test connection</button>
        <button class="btn btn-primary" data-action="next">Continue</button>
        <span class="key">${enterKeyHint('continue')}</span>
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
      result.className = 'test-result';
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
      ${this.renderProgress()}
      <h1>Authentication.</h1>
      <p class="lede">If your fortress requires an auth token, paste it here. Tokens are stored in your platform keychain. Leave blank if not required.</p>
      <label class="field">
        <span>Auth token</span>
        <input type="password" id="auth-token-input" value="${this.state.authToken ?? ''}" placeholder="optional" />
      </label>
      <div class="onb-actions">
        <button class="btn btn-link" data-action="back">Back</button>
        <button class="btn btn-primary" data-action="next">Continue</button>
        <span class="key">${enterKeyHint('continue')}</span>
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
      ${this.renderProgress()}
      <h1>Notifications.</h1>
      <p class="lede">Sanctuary surfaces approval requests as OS notifications. We need permission to show them.</p>
      <div class="test-result" id="notif-result"></div>
      <div class="onb-actions">
        <button class="btn btn-link" data-action="back">Back</button>
        <button class="btn btn-secondary" data-action="request">Request permission</button>
        <button class="btn btn-primary" data-action="next">Continue</button>
        <span class="key">${enterKeyHint('continue')}</span>
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
      ${this.renderProgress()}
      <h1>You're set up.</h1>
      <p class="lede">Sanctuary is now watching your fortress. The menubar icon shows pending approvals at a glance.</p>
      <div class="onb-success">
        <div class="onb-success-head">
          <span class="check"></span>
          <span>setup complete</span>
        </div>
      </div>
      <div class="onb-actions">
        <button class="btn btn-primary" data-action="finish">Done</button>
        <span class="key">${enterKeyHint('to finish')}</span>
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

// Enter-key hint. Uses U+21B5 (Downwards Arrow With Corner Leftwards),
// which renders cleanly in the menubar's system font without forcing a
// glyph fallback. Replaceable via build-time substitution if a future
// platform needs an alternative.
function enterKeyHint(suffix: string): string {
  return `↵ ${suffix}`;
}
