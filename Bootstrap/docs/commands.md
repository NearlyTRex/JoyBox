# Commands

[← Docs index](README.md)

Everyday `bootstrap.py` commands. Swap `local_ubuntu` for `remote_ubuntu -s 0` to target a
server instead.

```bash
# Check what's installed
python3 bootstrap.py -a status -t local_ubuntu

# Check specific components
python3 bootstrap.py -a status -t local_ubuntu --components chrome brave vscodium

# Dry run - see what would happen
python3 bootstrap.py -a setup -t local_ubuntu -p -v

# Force reinstall a component
python3 bootstrap.py -a setup -t local_ubuntu --components brave -f

# Uninstall everything
python3 bootstrap.py -a teardown -t local_ubuntu

# Capture current dotfiles into the repo (version-controlled snapshot)
python3 bootstrap.py -a backup -t local_ubuntu --components dotfiles

# Verbose output
python3 bootstrap.py -a setup -t local_ubuntu -v
```

## Flags

| Flag | Meaning |
|------|---------|
| `-a`, `--action` | `setup`, `teardown`, `status`, or `backup` |
| `-t`, `--type` | Environment type (`local_ubuntu`, `remote_ubuntu`) |
| `-s`, `--server_index` | Server index from `JoyBox.ini` (required for `remote_ubuntu`) |
| `-c`, `--config_file` | Path to the config file (default `~/JoyBox.ini`) |
| `--components` | Specific components to act on (default: all) |
| `--list-components` | List available components for the type and exit |
| `-p`, `--pretend_run` | Dry run — show what would happen, change nothing |
| `-v`, `--verbose` | Verbose logging |
| `-f`, `--force` | Act even if the component is already installed/uninstalled |
| `-x`, `--exit_on_failure` | Stop on the first error instead of continuing |
