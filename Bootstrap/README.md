# JoyBox Bootstrap

Automated setup for my home system and web server. Instead of manually remembering and
installing all my software, this handles everything in one command.

## Quickstart

Fresh **Ubuntu / Pop!_OS / Linux Mint** desktop with nothing installed yet? One line installs
the prerequisites, clones the repo, and runs the setup:

```bash
curl -fsSL https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/install.sh | bash
```

It's idempotent — re-running updates the checkout and skips anything already installed. Pass
arguments straight through to `bootstrap.py`:

```bash
curl -fsSL https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/install.sh | bash -s -- -a setup -t local_ubuntu --components aptget chrome
```

Already have the repo cloned? Run it directly from the repo root:

```bash
cd /path/to/JoyBox

# First run - creates JoyBox.ini config, prompts for any needed values
python3 bootstrap.py -a setup -t local_ubuntu
```

Setting up a remote server instead:

```bash
# Requires server settings in JoyBox.ini (host, user, password)
python3 bootstrap.py -a setup -t remote_ubuntu -s 0
```

Want only part of it? Pass `--components`, or list what's available:

```bash
python3 bootstrap.py -a setup -t local_ubuntu --components aptget chrome brave
python3 bootstrap.py -t local_ubuntu --list-components
```

> Add `-p -v` (pretend run + verbose) to any command the first time to see what it would do
> without changing your system.

## Supported systems

| System | Target (`-t`) |
|--------|---------------|
| Ubuntu / Pop!_OS / Linux Mint (and other Ubuntu-based distros) | `local_ubuntu` |
| Remote Ubuntu server | `remote_ubuntu` |

## Documentation

| Guide | What it covers |
|-------|----------------|
| [Home System Setup](docs/home-setup.md) | Fresh desktop setup, what gets installed, and installing specific components. |
| [Web Server Setup](docs/server-setup.md) | Provisioning a remote Ubuntu server and its services. |
| [Configuration](docs/configuration.md) | The `JoyBox.ini` config file and its key settings. |
| [Commands](docs/commands.md) | Everyday commands — status, dry runs, force reinstall, teardown, backup. |
| [Dotfiles](docs/dotfiles.md) | How your shell config is managed non-destructively, plus backup / capture. |
| [Adding Software](docs/adding-software.md) | Adding packages and writing custom installers. |
