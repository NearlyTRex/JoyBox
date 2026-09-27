# Local Computer Setup

[← Docs index](../README.md)

Set up a fresh **Ubuntu / Pop!_OS / Linux Mint** (or any Ubuntu-based) desktop. They share the
same APT base, so they all use the `local_ubuntu` target.

## Quick steps

```bash
# 1. Install. Clones to ~/Repositories/JoyBox, creates ~/JoyBox.ini, asks which components
#    to set up (Enter takes all of them), then sets them up
curl -fsSL https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/install.sh | bash

# 2. Open a new terminal so the shell config and PATH are picked up

# 3. Fill in ~/JoyBox.ini (see Configuration), keeping secrets in 1Password (see Secrets)

# 4. Re-run to pick up anything that needed a setting
cd ~/Repositories/JoyBox
python3 bootstrap.py -a setup -t local_ubuntu
```

Already have the repo cloned? Skip step 1 and run step 4 from the checkout.

**Check it worked:**

```bash
python3 bootstrap.py -a status -t local_ubuntu   # every component installed
which master_backup                              # ~/.venv/bin/master_backup
```

Add `-p -v` to any `bootstrap.py` command the first time to see what it would do without
changing anything.

## What the installer does

It installs `git` and `python3` if they are missing, clones to `$HOME/Repositories/JoyBox`, and
runs `bootstrap.py -a setup -t local_ubuntu --interactive`, which lists the components and asks
which to set up:

```text
Selection: 1-6 steam      # the first six, plus steam
Selection: -virtualbox -wine   # everything except these two
Selection:                # (Enter) everything
```

With no terminal to prompt on (cloud-init, CI) it sets up everything without asking. A component
that fails does not stop the others; the failures are listed at the end and the installer exits
non-zero. Override the destination or branch with the
`JOYBOX_DIR` / `JOYBOX_REF` environment variables, and pass extra `bootstrap.py` arguments after
`bash -s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/install.sh | bash -s -- -a setup -t local_ubuntu --components aptget chrome
```

Re-running is safe: the checkout is fast-forwarded and anything already installed is skipped.

## The JoyBox commands

JoyBox is a Python package, and the `python` component installs this checkout into `~/.venv` in
editable mode. pip creates one command per entry in `[project.scripts]` in `pyproject.toml`
(`master_backup`, `build_autoinstall_iso`, …) in `~/.venv/bin`, which the `dotfiles` component
puts on your `PATH`. Editable means changes to the code take effect immediately; a command added
to `[project.scripts]` since the last setup appears once the package is reinstalled:

```bash
~/.venv/bin/pip install --editable ~/Repositories/JoyBox[dev,decompiler]
```

What each command does is in the [command reference](../reference/man/README.md), and the flags
they all share are in [Using the tools](../guides/using-the-tools.md).

`setup_tools` is a different thing: it installs the *third-party* programs the commands use
(7-Zip, rclone and the like). See [Tools & Emulators](../guides/tools-emulators.md).

## What gets installed

Everything, unless you pick components:

- **Dev tools**: build-essential, cmake, git, golang, nodejs, dotnet, python tools, Qt dev
  packages, ripgrep, GitHub CLI
- **AI/LLM**: Claude Code CLI, Ollama, npm coding tools (ccusage, Codex, OpenCode)
- **Editors/IDEs**: VSCodium, GitKraken
- **Browsers**: Chrome, Brave, Firefox
- **Apps**: 1Password, GIMP, VLC, Handbrake, Audacity, OBS alternatives
- **Gaming**: Steam, SteamCMD, DXVK, Wine
- **Virtualization**: VirtualBox, QEMU/KVM, virt-manager
- **Utilities**: KDiff3, Meld, Okular, Remmina, and many more
- **Flatpaks**: Discord, Signal, Telegram, IntelliJ, Heroic Launcher, etc.
- **Python packages**: All my commonly used pip packages

## Install Specific Components Only

```bash
# Just browsers and dev tools
python3 bootstrap.py -a setup -t local_ubuntu --components aptget chrome brave vscodium gitkraken

# Pick from a menu
python3 bootstrap.py -a setup -t local_ubuntu --interactive

# See what's available
python3 bootstrap.py -t local_ubuntu --list-components
```

## Available Components (Home)

| Component | What it does |
|-----------|--------------|
| `config` | Configuration setup |
| `dconf` | Desktop dconf/gsettings settings |
| `dotfiles` | Dot files installation |
| `githooks` | Activate the repo's git hooks |
| `python` | Python venv, JoyBox itself (editable) and the other venv tools |
| `wrappers` | `python3`/`pip3` in ~/.joybox/bin, pointing at the venv |
| `aptget` | All APT packages |
| `awscli` | AWS CLI |
| `flatpak` | Flatpak apps |
| `node` | Global npm packages (ccusage, Codex, OpenCode) |
| `chrome` | Google Chrome |
| `claude` | Claude Code CLI |
| `deno` | Deno JS runtime |
| `brave` | Brave Browser |
| `gh` | GitHub CLI |
| `gitkraken` | GitKraken |
| `ollama` | Ollama local LLM runtime |
| `onepassword` | 1Password |
| `steam` | Steam gaming platform |
| `sysctl` | Kernel sysctl tweaks |
| `udev` | USB device rules |
| `virtualbox` | VirtualBox |
| `vscodium` | VSCodium |
| `wine` | Wine + dependencies |
| `xorg` | Xorg input tweaks (remaps Magic Trackpad middle-click to left) |

## Where to go next

- [Configuration](../reference/configuration.md) — what lands in `JoyBox.ini`.
- [Secrets](../reference/secrets.md) — keeping passwords and keys in 1Password instead.
- [Bootstrap commands](../reference/bootstrap-commands.md) — status checks, dry runs, teardown.
- [Dotfiles](../reference/dotfiles.md) — how your shell config is managed.
