#!/usr/bin/env bash
set -euo pipefail

pkg="${1:?usage: ci-arch-lifecycle.sh <pkg.tar.zst> [--noextract-witness]}"
mode="${2:-default}"
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
  chown -R build:build "$root"
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
  local phrase="${1:?expect_refused requires a guard phrase}"
  shift
  if "$@" >"$evidence/$label.out" 2>"$evidence/$label.err"; then
    echo "$label unexpectedly succeeded" >&2
    exit 1
  fi
  cat "$evidence/$label.out" "$evidence/$label.err" >"$evidence/$label.combined"
  grep -F 'Castle Wall package guard refused:' "$evidence/$label.combined" >/dev/null
  grep -F "$phrase" "$evidence/$label.combined" >/dev/null
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
  # Capture, never pipe: under `set -o pipefail` a disabled unit makes
  # `systemctl is-enabled` exit 1 and an inactive one makes `is-active` exit 3,
  # so `systemctl ... | grep` aborted this script on a correct fresh install
  # with no message (CI run 37404360159). The comparison below is the assertion.
  [[ "$(systemctl is-enabled sanctuary-castle-wall.service 2>/dev/null || true)" == disabled ]]
  [[ "$(systemctl is-active sanctuary-castle-wall.service 2>/dev/null || true)" == inactive ]]
  [[ ! -e /etc/sanctuary || -z "$(find /etc/sanctuary -mindepth 1 -maxdepth 1 -print -quit)" ]]
}

assert_systemd
id build >/dev/null 2>&1 || useradd -m build
# mktemp creates a root-owned 0700 parent; makepkg as build needs access to its scratch PKGBUILD tree.
chown build:build "$work"
pacman -Syu --noconfirm --needed base-devel zstd systemd nftables iproute2 util-linux shadow python libnetfilter_queue >/dev/null

identity_path=/usr/lib/sanctuary-castle-wall/build-identity
identity_rel=${identity_path#/}
guard_path=/usr/share/libalpm/scripts/sanctuary-castle-wall-guard

if [[ "$mode" == --noextract-witness ]]; then
  record 'NoExtract witness keeps the image pacman.conf rules; base failure was captured in run 37365438647 attempt 2'
  pacman-conf NoExtract | grep -Fx 'usr/share/doc/*' >/dev/null
  expect_ok noextract-head-install pacman -U --noconfirm "$pkg"
  pacman -Qkk sanctuary-castle-wall >"$evidence/noextract-head-qkk.out"
  if pacman -Ql sanctuary-castle-wall | grep -F '/usr/share/doc' >"$evidence/noextract-head-doc-paths.out"; then
    echo "NoExtract head package listed usr/share/doc payload paths" >&2
    exit 1
  fi
  installed_sha="$(sha256sum "$identity_path" | cut -d' ' -f1)"
  guard_sha="$(awk -F"'" 'NR == 2 && $1 == "IDENTITY_SHA256 = " {print $2}' "$guard_path")"
  [[ "$installed_sha" == "$guard_sha" ]]
  expect_ok noextract-inert-remove pacman -R --noconfirm sanctuary-castle-wall
  expect_ok noextract-reinstall pacman -U --noconfirm "$pkg"
  install -d -m 0755 /etc/sanctuary
  printf provisioned >/etc/sanctuary/provisioned
  provisioned_refusal='runtime/config entry present under /etc/sanctuary'
  expect_refused noextract-remove-provisioned "$provisioned_refusal" pacman -R --noconfirm sanctuary-castle-wall
  expect_refused noextract-remove-dd-provisioned "$provisioned_refusal" pacman -Rdd --noconfirm sanctuary-castle-wall
  mask_hook 00-sanctuary-castle-wall-remove-guard.hook
  expect_ok noextract-remove-provisioned-masked pacman -R --noconfirm sanctuary-castle-wall
  unmask_hooks
  rm -f /etc/sanctuary/provisioned

  sed -i "/^\[options\]/a NoExtract = $identity_rel" /etc/pacman.conf
  pacman-conf NoExtract | grep -Fx "$identity_rel" >/dev/null
  expect_ok noextract-missing-identity-install pacman -U --noconfirm "$pkg"
  [[ ! -e "$identity_path" ]]
  if pacman -Qkk sanctuary-castle-wall >"$evidence/noextract-missing-qkk.out" 2>"$evidence/noextract-missing-qkk.err"; then
    echo "missing identity install unexpectedly passed pacman -Qkk" >&2
    exit 1
  fi
  identity_absent='build identity absent'
  expect_refused noextract-missing-inert-remove "$identity_absent" pacman -R --noconfirm sanctuary-castle-wall
  install -d -m 0755 /etc/sanctuary
  printf provisioned >/etc/sanctuary/provisioned
  expect_refused noextract-missing-provisioned-remove "$identity_absent" pacman -R --noconfirm sanctuary-castle-wall
  expect_refused noextract-missing-provisioned-remove-dd "$identity_absent" pacman -Rdd --noconfirm sanctuary-castle-wall
  record 'NoExtract identity-present and missing-identity witnesses passed'
  exit 0
fi

if [[ "$mode" != default ]]; then
  echo "unsupported lifecycle mode: $mode" >&2
  exit 1
fi

# The official archlinux container image ships NoExtract rules (usr/share/doc/*,
# locales, help) that stock Arch and Omarchy do not have. The build identity the
# P1 guard bound to lived under usr/share/doc, so under those rules a fresh
# install never received it and `pacman -Qkk` reported an altered file before
# any hook ran (seen 2026-10-05: "/usr/share/doc (No such file or directory),
# 1 altered file"). P2b has a separate NoExtract witness that keeps the rule.
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

record 'first install is not refused'
expect_ok first-install pacman -U --noconfirm "$pkg"
assert_inert

scratch_pkg sanctuary-castle-wall 0.1.1 "$work/upgrade.pkg.tar.zst"
scratch_pkg sanctuary-castle-wall 0.0.9 "$work/downgrade.pkg.tar.zst"
scratch_pkg unrelated-hold-witness 1.0.0 "$work/unrelated.pkg.tar.zst"
sbin_conflict_extra=$'  install -d "$pkgdir/usr/sbin"\n  printf conflict >"$pkgdir/usr/sbin/sanctuary-linux"'
scratch_pkg sbin-conflict 1.0.0 "$work/sbin.pkg.tar.zst" "$sbin_conflict_extra"

# Must match UPGRADE_REFUSAL in sanctuary-castle-wall-guard.py.
upgrade_refusal='in-place Castle Wall upgrade, reinstall and downgrade are unsupported; retire this host and cold-install a new package'
# Must match PROVISIONED_FOOTPRINT_REFUSAL in sanctuary-castle-wall-guard.py.
provisioned_refusal='runtime/config entry present under /etc/sanctuary'

expect_refused upgrade "$upgrade_refusal" pacman -U --noconfirm "$work/upgrade.pkg.tar.zst"
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok upgrade-masked pacman -U --noconfirm "$work/upgrade.pkg.tar.zst"
unmask_hooks
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok restore-original-after-upgrade pacman -U --noconfirm "$pkg"
unmask_hooks

expect_refused reinstall "$upgrade_refusal" pacman -U --noconfirm "$pkg"
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok reinstall-masked pacman -U --noconfirm "$pkg"
unmask_hooks

expect_refused downgrade "$upgrade_refusal" pacman -U --noconfirm "$work/downgrade.pkg.tar.zst"
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok downgrade-masked pacman -U --noconfirm "$work/downgrade.pkg.tar.zst"
expect_ok restore-original-after-downgrade pacman -U --noconfirm "$pkg"
unmask_hooks

expect_refused foreign-alone "$upgrade_refusal" pacman -U --noconfirm "$work/upgrade.pkg.tar.zst"
expect_refused foreign-batched "$upgrade_refusal" pacman -U --noconfirm "$work/upgrade.pkg.tar.zst" "$work/unrelated.pkg.tar.zst"
# The claim is "held back with it": the AbortOnFail refusal must have aborted the
# whole transaction, so the unrelated package in the same batch stays uninstalled.
if pacman -Q unrelated-hold-witness >/dev/null 2>&1; then
  echo "foreign-batched refusal did not hold back the unrelated package" >&2
  exit 1
fi
record 'held back: unrelated package in the refused batch stayed uninstalled'
mask_hook 00-sanctuary-castle-wall-upgrade-guard.hook
expect_ok foreign-batched-masked pacman -U --noconfirm "$work/upgrade.pkg.tar.zst" "$work/unrelated.pkg.tar.zst"
expect_ok restore-original-after-foreign pacman -U --noconfirm "$pkg"
unmask_hooks

install -d -m 0755 /etc/sanctuary
printf provisioned >/etc/sanctuary/provisioned
expect_refused remove-provisioned "$provisioned_refusal" pacman -R --noconfirm sanctuary-castle-wall
expect_refused remove-dd-provisioned "$provisioned_refusal" pacman -Rdd --noconfirm sanctuary-castle-wall
mask_hook 00-sanctuary-castle-wall-remove-guard.hook
expect_ok remove-provisioned-masked pacman -R --noconfirm sanctuary-castle-wall
unmask_hooks
expect_ok reinstall-after-remove-masked pacman -U --noconfirm "$pkg"
mask_hook 00-sanctuary-castle-wall-remove-guard.hook
expect_ok remove-dd-provisioned-masked pacman -Rdd --noconfirm sanctuary-castle-wall
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
