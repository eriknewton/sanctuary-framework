# Castle Wall Arch Package

This first Arch slice builds a third-party `sanctuary-castle-wall` package for cold install testing. In-place upgrades, reinstalls and downgrades are refused by pacman hooks; the supported path is to retire the host and cold-install a new package.

The hooks guard against accidental and unattended package replacement, not against root. The package does not guard its own first install. Failure mode: a first install can place files before the package's own hooks exist, so first-install claims need separate evidence.

A routine `omarchy update` does not include this package while no same-named AUR package exists. If one appears, `yay` can refuse it inside the update, and other AUR packages in that same transaction can be held back with it. The update can still exit 0 with no end-of-run warning, so check `pacman -Q sanctuary-castle-wall` after an update. Failure mode: the package can remain unchanged while the update UI looks finished.

Kernel, systemd and nftables updates are outside this package claim. Reboot after those updates. Failure mode: a same-boot substrate change has not been drilled for this package.

`sanctuary-linux` does not yet operate on Arch. This package records the Arch CLI path deviation, but the Rust package checks still expect the Ubuntu install identity until the portability slice lands.
