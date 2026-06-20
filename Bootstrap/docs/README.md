# JoyBox Bootstrap Documentation

Detail pages for the bootstrap setup. The [main README](../README.md) has the overview and
quickstart; these guides cover each area in full.

## Contents

| Guide | What it covers |
|-------|----------------|
| [Home System Setup](home-setup.md) | Setting up a fresh Ubuntu / Pop!_OS / Linux Mint desktop, the full component list, and installing specific components. |
| [Web Server Setup](server-setup.md) | Provisioning a remote Ubuntu server: web server, SSL, services, and the server component list. |
| [Configuration](configuration.md) | The `JoyBox.ini` config file and its key settings. |
| [Commands](commands.md) | Everyday `bootstrap.py` commands — status, dry runs, force reinstall, teardown, backup. |
| [Dotfiles](dotfiles.md) | How the `dotfiles` component manages your shell config non-destructively, plus backup / capture. |
| [Adding Software](adding-software.md) | Adding APT / Flatpak / Python packages and writing custom installers, with the file-structure reference. |

## Supported systems

| System | Target (`-t`) |
|--------|---------------|
| Ubuntu / Pop!_OS / Linux Mint (and other Ubuntu-based distros) | `local_ubuntu` |
| Remote Ubuntu server | `remote_ubuntu` |

All Ubuntu-based desktop distributions use the `local_ubuntu` target — they share the same APT
base, so no separate target is needed.

## Conventions used in these guides

- Run everything from the repo root (`cd /path/to/JoyBox`).
- Every example is copy-pasteable. Add `-p -v` (pretend run + verbose) the first time you run
  anything to see what would happen without changing your system.
- Components are installed in order and uninstalled in reverse order; already-installed
  components are skipped (use `-f` to force).
