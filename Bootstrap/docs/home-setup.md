# Home System Setup

[← Docs index](README.md)

Set up a fresh **Ubuntu / Pop!_OS / Linux Mint** (or any Ubuntu-based) desktop in one command.
All of these distros share the same APT base, so they all use the `local_ubuntu` target.

```bash
cd /path/to/JoyBox

# First run - creates JoyBox.ini config, prompts for any needed values
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
| `dotfiles` | Dot files installation |
| `githooks` | Activate the repo's git hooks (secret-scanning pre-commit) |
| `python` | Python venv + pip packages |
| `wrappers` | Script wrappers in ~/.joybox/bin |
| `aptget` | All APT packages (dev tools, libs, apps) |
| `awscli` | AWS CLI |
| `flatpak` | Flatpak apps (Discord, Signal, etc.) |
| `ccusage` | Claude Code usage monitoring |
| `chrome` | Google Chrome (adds repo) |
| `claude` | Claude Code CLI |
| `deno` | Deno JS runtime (yt-dlp's YouTube challenge solver needs it) |
| `brave` | Brave Browser (adds repo) |
| `gh` | GitHub CLI (adds repo) |
| `gitkraken` | GitKraken (downloads latest .deb) |
| `ollama` | Ollama local LLM runtime |
| `onepassword` | 1Password (adds repo) |
| `steam` | Steam gaming platform |
| `udev` | USB/controller device rules |
| `virtualbox` | VirtualBox (Oracle repo) |
| `vscodium` | VSCodium (adds repo) |
| `wine` | Wine + dependencies |

## Where to go next

- [Configuration](configuration.md) — what lands in `JoyBox.ini`.
- [Commands](commands.md) — status checks, dry runs, teardown.
- [Dotfiles](dotfiles.md) — how your shell config is managed.
