// Notification backend abstraction. macOS implementation uses Tauri's notification plugin
// (which routes through UNUserNotificationCenter). Linux + Windows are stubbed.

import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from '@tauri-apps/plugin-notification';

export interface NotificationBackend {
  requestPermission(): Promise<boolean>;
  fire(title: string, body: string, onClick?: () => void): Promise<void>;
}

class MacOSNotificationBackend implements NotificationBackend {
  // Rate limiting: max one notification per 30s for the same agent + tool combination.
  private lastFiredAt = new Map<string, number>();
  private readonly rateLimitMs = 30_000;
  private clickHandlers: Array<() => void> = [];

  async requestPermission(): Promise<boolean> {
    const already = await isPermissionGranted();
    if (already) return true;
    const result = await requestPermission();
    return result === 'granted';
  }

  async fire(title: string, body: string, onClick?: () => void): Promise<void> {
    const key = `${title}::${body.split(' ').slice(0, 3).join(' ')}`;
    const now = Date.now();
    const last = this.lastFiredAt.get(key) ?? 0;
    if (now - last < this.rateLimitMs) {
      // Coalesce: do not fire a second notification within 30s for the same key.
      return;
    }
    this.lastFiredAt.set(key, now);

    if (onClick) this.clickHandlers.push(onClick);

    await sendNotification({
      title,
      body,
    });
  }

  // Called when a notification is clicked. The plugin does not currently expose a
  // direct click handler in v2; the popover open is wired separately via tray events.
  // This method is here so a future Piece 2 wire-up has a hook point.
  fireClickHandlers(): void {
    for (const h of this.clickHandlers.splice(0)) {
      try {
        h();
      } catch (err) {
        console.error('notification click handler threw', err);
      }
    }
  }
}

class LinuxNotificationBackend implements NotificationBackend {
  async requestPermission(): Promise<boolean> {
    throw new Error('LinuxNotificationBackend not implemented; libnotify ships in Sprint Piece 2 or v1.2.5');
  }
  async fire(_title: string, _body: string, _onClick?: () => void): Promise<void> {
    throw new Error('LinuxNotificationBackend not implemented; libnotify ships in Sprint Piece 2 or v1.2.5');
  }
}

class WindowsNotificationBackend implements NotificationBackend {
  async requestPermission(): Promise<boolean> {
    throw new Error('WindowsNotificationBackend not implemented; WinRT Toast ships in Phase 2 (v1.3+)');
  }
  async fire(_title: string, _body: string, _onClick?: () => void): Promise<void> {
    throw new Error('WindowsNotificationBackend not implemented; WinRT Toast ships in Phase 2 (v1.3+)');
  }
}

let cached: NotificationBackend | null = null;

export function getNotificationBackend(): NotificationBackend {
  if (cached) return cached;
  const platform = detectPlatform();
  switch (platform) {
    case 'macos':
      cached = new MacOSNotificationBackend();
      break;
    case 'linux':
      cached = new LinuxNotificationBackend();
      break;
    case 'windows':
      cached = new WindowsNotificationBackend();
      break;
  }
  return cached;
}

function detectPlatform(): 'macos' | 'linux' | 'windows' {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('mac')) return 'macos';
  if (ua.includes('linux')) return 'linux';
  if (ua.includes('windows')) return 'windows';
  return 'macos';
}
