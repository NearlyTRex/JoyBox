# Home System Setup

[← Docs index](README.md)

Set up a fresh **Ubuntu / Pop!_OS / Linux Mint** (or any Ubuntu-based) desktop in one command.
All of these distros share the same APT base, so they all use the `local_ubuntu` target.

### From a bare machine

If JoyBox isn't even cloned yet, the installer script handles prerequisites, the clone, and the
setup in one go:

```bash
curl -fsSL https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/install.sh | bash
```

It installs `git` + `python3` if missing, clones to `$HOME/Repositories/JoyBox`, then runs the
setup below. Override the destination or branch with `JOYBOX_DIR` / `JOYBOX_REF` env vars, and
pass extra `bootstrap.py` arguments after `bash -s --`.

### From a cloned repo

```bash
cd /path/to/JoyBox

# First run - creates ~/JoyBox.ini from defaults if it doesn't exist yet
python3 bootstrap.py -a setup -t local_ubuntu
```

This installs:
- **Dev tools**: build-essential, cmake, git, golang, nodejs, dotnet, python tools, Qt dev packages, ripgrep, GitHub CLI
- **AI/LLM**: Claude Code CLI, Ollama, ccusage (usage monitoring)
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
| `ccusage` | Claude Code usage monitoring |
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

- [Configuration](configuration.md) — what lands in `JoyBox.ini`.
- [Commands](commands.md) — status checks, dry runs, teardown.
- [Dotfiles](dotfiles.md) — how your shell config is managed.
