# Castle Wall Arch Package

This first Arch slice builds a third-party `sanctuary-castle-wall` package for cold install testing. In-place upgrades, reinstalls and downgrades are refused by pacman hooks; the supported path is to retire the host and cold-install a new package.

The hooks guard against accidental and unattended package replacement, not against root. The package does not guard its own first install. Failure mode: a first install can place files before the package's own hooks exist, so first-install claims need separate evidence.

A routine `omarchy update` does not include this package while no same-named AUR package exists. If one appears, `yay` can refuse it inside the update, and other AUR packages in that same transaction can be held back with it. The update can still exit 0 with no end-of-run warning, so check `pacman -Q sanctuary-castle-wall` after an update. Failure mode: the package can remain unchanged while the update UI looks finished.

Kernel, systemd and nftables updates are outside this package claim. Reboot after those updates. Failure mode: a same-boot substrate change has not been drilled for this package.

The package's build identity is installed under `/usr/share/doc/sanctuary-castle-wall/`, and the remove guard binds to it. A host whose `pacman.conf` excludes `usr/share/doc/*` from extraction (the official Arch container image does; stock Arch and Omarchy do not) never receives that file. Such hosts are outside this package's claim. Failure mode: `pacman -Qkk sanctuary-castle-wall` reports an altered file right after install, and the remove guard refuses every removal there because its identity is absent; removal there is an operator action outside the guard.

`sanctuary-linux` does not yet operate on Arch. This package records the Arch CLI path deviation, but the Rust package checks still expect the Ubuntu install identity until the portability slice lands.

<!-- scratch witness d: touches an allowlisted trigger path so the gate is ENFORCED; never merged -->
