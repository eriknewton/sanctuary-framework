// Menubar tray abstraction. macOS implementation calls into the Rust backend via Tauri commands.
// Linux + Windows are stubbed in Sprint Piece 1; full implementations land in Piece 2 / Phase 2.

import { invoke } from '@tauri-apps/api/core';

export type TrayIconVariant = 'clear' | 'alert';

export interface MenubarBackend {
  setIcon(variant: TrayIconVariant): Promise<void>;
  setBadge(count: number): Promise<void>;
  showPopover(): Promise<void>;
  hidePopover(): Promise<void>;
  onTrayClick(handler: () => void): void;
}

class MacOSMenubarBackend implements MenubarBackend {
  private trayClickHandlers: Array<() => void> = [];

  async setIcon(variant: TrayIconVariant): Promise<void> {
    await invoke('tray_set_icon', { variant });
  }

  async setBadge(count: number): Promise<void> {
    await invoke('tray_set_badge', { count });
  }

  async showPopover(): Promise<void> {
    await invoke('popover_show');
  }

  async hidePopover(): Promise<void> {
    await invoke('popover_hide');
  }

  onTrayClick(handler: () => void): void {
    this.trayClickHandlers.push(handler);
  }

  // Called by Rust via emit when the tray is clicked.
  fireTrayClick(): void {
    for (const h of this.trayClickHandlers) {
      try {
        h();
      } catch (err) {
        console.error('tray click handler threw', err);
      }
    }
  }
}

class LinuxMenubarBackend implements MenubarBackend {
  async setIcon(_variant: TrayIconVariant): Promise<void> {
    throw new Error('LinuxMenubarBackend not implemented; ships in Sprint Piece 2 or v1.2.5');
  }
  async setBadge(_count: number): Promise<void> {
    throw new Error('LinuxMenubarBackend not implemented; ships in Sprint Piece 2 or v1.2.5');
  }
  async showPopover(): Promise<void> {
    throw new Error('LinuxMenubarBackend not implemented; ships in Sprint Piece 2 or v1.2.5');
  }
  async hidePopover(): Promise<void> {
    throw new Error('LinuxMenubarBackend not implemented; ships in Sprint Piece 2 or v1.2.5');
  }
  onTrayClick(_handler: () => void): void {
    throw new Error('LinuxMenubarBackend not implemented; ships in Sprint Piece 2 or v1.2.5');
  }
}

class WindowsMenubarBackend implements MenubarBackend {
  async setIcon(_variant: TrayIconVariant): Promise<void> {
    throw new Error('WindowsMenubarBackend not implemented; ships in Phase 2 (v1.3+)');
  }
  async setBadge(_count: number): Promise<void> {
    throw new Error('WindowsMenubarBackend not implemented; ships in Phase 2 (v1.3+)');
  }
  async showPopover(): Promise<void> {
    throw new Error('WindowsMenubarBackend not implemented; ships in Phase 2 (v1.3+)');
  }
  async hidePopover(): Promise<void> {
    throw new Error('WindowsMenubarBackend not implemented; ships in Phase 2 (v1.3+)');
  }
  onTrayClick(_handler: () => void): void {
    throw new Error('WindowsMenubarBackend not implemented; ships in Phase 2 (v1.3+)');
  }
}

let cached: MenubarBackend | null = null;
let cachedMacOS: MacOSMenubarBackend | null = null;

export function getMenubarBackend(): MenubarBackend {
  if (cached) return cached;
  const platform = detectPlatform();
  switch (platform) {
    case 'macos': {
      cachedMacOS = new MacOSMenubarBackend();
      cached = cachedMacOS;
      break;
    }
    case 'linux':
      cached = new LinuxMenubarBackend();
      break;
    case 'windows':
      cached = new WindowsMenubarBackend();
      break;
  }
  return cached;
}

export function getMacOSBackendForEvents(): MacOSMenubarBackend | null {
  return cachedMacOS;
}

function detectPlatform(): 'macos' | 'linux' | 'windows' {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('mac')) return 'macos';
  if (ua.includes('linux')) return 'linux';
  if (ua.includes('windows')) return 'windows';
  return 'macos';
}
