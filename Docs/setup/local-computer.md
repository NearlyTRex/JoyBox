# Local Computer Setup

[← Docs index](../README.md)

Set up a fresh **Ubuntu / Pop!_OS / Linux Mint** (or any Ubuntu-based) desktop. They share the
same APT base, so they all use the `local_ubuntu` target.

## Quick steps

```bash
# 1. Install everything. Clones to ~/Repositories/JoyBox, creates ~/JoyBox.ini, then sets up
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
which master_backup                              # ~/.joybox/bin/master_backup
```

Add `-p -v` to any `bootstrap.py` command the first time to see what it would do without
changing anything.

## What the installer does

It installs `git` and `python3` if they are missing, clones to `$HOME/Repositories/JoyBox`, and
runs `bootstrap.py -a setup -t local_ubuntu`. Override the destination or branch with the
`JOYBOX_DIR` / `JOYBOX_REF` environment variables, and pass extra `bootstrap.py` arguments after
`bash -s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/install.sh | bash -s -- -a setup -t local_ubuntu --components aptget chrome
```

Re-running is safe: the checkout is fast-forwarded and anything already installed is skipped.

## The JoyBox commands

Every script in `Scripts/bin` gets a shim of the same name in `~/.joybox/bin` (`master_backup`,
`build_autoinstall_iso`, …), which the `dotfiles` component puts on your `PATH`. The shims are
made by the `wrappers` component. A script added since the last setup has no shim until they are
rebuilt:

```bash
python3 bootstrap.py -a setup -t local_ubuntu --components wrappers -f
```

`-f` is needed because the component is already installed and would otherwise be skipped. What
each command does is in the [command reference](../reference/man/README.md), and the flags they
all share are in [Using the tools](../guides/using-the-tools.md).

`setup_tools` is a different thing: it installs the *third-party* programs the commands use
(7-Zip, rclone and the like). See [Tools & Emulators](../guides/tools-emulators.md).

## What gets installed

Everything, unless you pick components:
- **Dev tools**: build-essential, cmake, git, golang, nodejs, dotnet, python tools, Qt dev packages, ripgrep, GitHub CLI
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
| `python` | Python venv + pip packages |
| `wrappers` | Script wrappers in ~/.joybox/bin |
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
