#!/usr/bin/env bash
set -euo pipefail

pkg="${1:?usage: ci-arch-lifecycle.sh <pkg.tar.zst>}"
pkg="$(realpath "$pkg")"
work="$(mktemp -d)"
evidence="${EVIDENCE_DIR:-$work/evidence}"
mkdir -p "$evidence"

assert_systemd() {
  [[ "$(cat /proc/1/comm)" == systemd ]]
  systemctl is-system-running --wait >/dev/null || [[ "$(systemctl is-system-running)" =~ ^(running|degraded)$ ]]
}

record() {
  printf '%s\n' "$*" | tee -a "$evidence/lifecycle.log"
}

scratch_pkg() {
  local name="$1" version="$2" out="$3" extra="${4:-}"
  local root="$work/$name-$version"
  mkdir -p "$root"
  cat >"$root/PKGBUILD" <<PKG
pkgname=$name
pkgver=$version
pkgrel=1
pkgdesc='scratch package for Castle Wall lifecycle CI'
arch=('any')
license=('LicenseRef-Scratch')
source=()
sha256sums=()
package() {
  install -d "\$pkgdir/usr/share/$name"
  printf '%s\n' "$name $version" >"\$pkgdir/usr/share/$name/payload.txt"
$extra
}
PKG
  runuser -u build -- bash -lc "cd '$root' && makepkg --noconfirm --nodeps >/dev/null"
  cp "$root"/*.pkg.tar.zst "$out"
}

mask_hook() {
  local hook="$1"
  install -d -m 0755 /etc/pacman.d/hooks
  printf '[Trigger]\nOperation = Install\nType = Package\nTarget = __never_matches__\n\n[Action]\nDescription = Mask Castle Wall test hook\nWhen = PreTransaction\nExec = /usr/bin/true\n' >"/etc/pacman.d/hooks/$hook"
}

unmask_hooks() {
  rm -f /etc/pacman.d/hooks/00-sanctuary-castle-wall-upgrade-guard.hook
  rm -f /etc/pacman.d/hooks/00-sanctuary-castle-wall-remove-guard.hook
}

expect_refused() {
  local label="$1"
  shift
  if "$@" >"$evidence/$label.out" 2>"$evidence/$label.err"; then
    echo "$label unexpectedly succeeded" >&2
    exit 1
  fi
  grep -F 'Castle Wall package guard refused:' "$evidence/$label.err" >/dev/null
  record "refused: $label"
}

expect_ok() {
  local label="$1"
  shift
  "$@" >"$evidence/$label.out" 2>"$evidence/$label.err"
  record "admitted: $label"
}

assert_inert() {
  pacman -Qkk sanctuary-castle-wall
  systemctl is-enabled sanctuary-castle-wall.service 2>/dev/null | grep -Fx disabled >/dev/null
  systemctl is-active sanctuary-castle-wall.service 2>/dev/null | grep -Fx inactive >/dev/null
  [[ ! -e /etc/sanctuary || -z "$(find /etc/sanctuary -mindepth 1 -maxdepth 1 -print -quit)" ]]
}

assert_systemd
# The official archlinux container image ships NoExtract rules (usr/share/doc/*,
# locales, help) that stock Arch and Omarchy do not have. The build identity the
# guard binds to lives under usr/share/doc, so under those rules a fresh install
# never receives it and `pacman -Qkk` reports an altered file before any hook runs
# (seen 2026-10-05: "/usr/share/doc (No such file or directory), 1 altered file").
# The proof target is a default pacman.conf, so strip the image's rules and refuse
# to continue if any NoExtract remains; a silent skip here would test a host that
# does not exist. Failure mode: the first-install witness fails on `-Qkk` with no
# refusal text, which reads like a package defect rather than a container artifact.
sed -i '/^[[:space:]]*NoExtract/d' /etc/pacman.conf
if compgen -G '/etc/pacman.d/*.conf' >/dev/null; then sed -i '/^[[:space:]]*NoExtract/d' /etc/pacman.d/*.conf; fi
if [[ -n "$(pacman-conf NoExtract)" ]]; then
  echo "container pacman.conf still carries NoExtract rules; the lifecycle witness needs default extraction" >&2
  exit 1
fi
record 'container pacman.conf has no NoExtract rules (default extraction, as on stock Arch and Omarchy)'
id build >/dev/null 2>&1 || useradd -m build
pacman -Sy --noconfirm --needed base-devel zstd systemd nftables iproute2 util-linux shadow python libnetfilter_queue >/dev/null

record 'first install is not refused'
expect_ok first-install pacman -U --noconfirm "$pkg"
assert_inert

scratch_pkg sanctuary-castle-wall 0.1.1 "$work/upgrade.pkg.tar.zst"
scratch_pkg sanctuary-castle-wall 0.0.9 "$work/downgrade.pkg.tar.zst"
scratch_pkg unrelated-hold-witness 1.0.0 "$work/unrelated.pkg.tar.zst"
scratch_pkg sbin-conflict 1.0.0 "$work/sbin.pkg.tar.zst" "  install -d \"\$pkgdir/usr/sbin\"\n  printf conflict >\"\$pkgdir/usr/sbin/sanctuary-linux\"\n"

expect_refused upgrade pacman -U --noconfirm "$work/upgrade.pkg.tar.zst"
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok upgrade-masked pacman -U --noconfirm "$work/upgrade.pkg.tar.zst"
unmask_hooks
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok restore-original-after-upgrade pacman -U --noconfirm "$pkg"
unmask_hooks

expect_refused reinstall pacman -U --noconfirm "$pkg"
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok reinstall-masked pacman -U --noconfirm "$pkg"
unmask_hooks

expect_refused downgrade pacman -U --noconfirm "$work/downgrade.pkg.tar.zst"
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok downgrade-masked pacman -U --noconfirm "$work/downgrade.pkg.tar.zst"
expect_ok restore-original-after-downgrade pacman -U --noconfirm "$pkg"
unmask_hooks

expect_refused foreign-alone pacman -U --noconfirm "$work/upgrade.pkg.tar.zst"
expect_refused foreign-batched pacman -U --noconfirm "$work/upgrade.pkg.tar.zst" "$work/unrelated.pkg.tar.zst"
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok foreign-batched-masked pacman -U --noconfirm "$work/upgrade.pkg.tar.zst" "$work/unrelated.pkg.tar.zst"
expect_ok restore-original-after-foreign pacman -U --noconfirm "$pkg"
unmask_hooks

install -d -m 0755 /etc/sanctuary
printf provisioned >/etc/sanctuary/provisioned
expect_refused remove-provisioned pacman -R --noconfirm sanctuary-castle-wall
expect_refused remove-dd-provisioned pacman -Rdd --noconfirm sanctuary-castle-wall
mask_hook 00-sanctuary-castle-wall-remove-guard.hook
expect_ok remove-provisioned-masked pacman -R --noconfirm sanctuary-castle-wall
unmask_hooks
rm -f /etc/sanctuary/provisioned

expect_ok reinstall-after-remove pacman -U --noconfirm "$pkg"
expect_ok inert-remove pacman -R --noconfirm sanctuary-castle-wall

if pacman -U --noconfirm "$work/sbin.pkg.tar.zst" >"$evidence/sbin-conflict.out" 2>"$evidence/sbin-conflict.err"; then
  echo "usr/sbin conflict witness unexpectedly installed" >&2
  exit 1
fi
grep -E 'conflicting files|exists in filesystem' "$evidence/sbin-conflict.err" >/dev/null
record 'usr/sbin conflict refused by pacman'
