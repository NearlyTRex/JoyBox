# setup_tools

Install, update, or rebuild the third-party tools JoyBox depends on.

## Synopsis

```
setup_tools [-k <packages>] [-f] [--clean] [-e] [-c] [options]
```

## Description

`setup_tools` installs the external helper programs that other JoyBox commands call —
e.g. `7-Zip`, `FFMpeg`, `RClone`, `Wine`, `Pegasus`, the store downloaders
(`Legendary`, `Nile`, `LGOGDownloader`, …), and more. Packages are defined in
`Scripts/lib/tools/*.py`; each knows how to download, install, and (optionally) configure
itself.

The process for each selected package:

1. Optionally clean the whole tools root (`--clean`) or the package's own install
   directory (`--force`) first.
2. Install it — online (download) by default, or from the local backup with `--offline`.
3. Optionally run its configuration step (`--configure`).

It is **idempotent**: a package already installed is skipped unless you `--force` or
`--clean`, so re-running simply fills in whatever is missing. Tools install under the
directory named by `[UserData.Dirs] tools_dir` in `~/JoyBox.ini`.

> This installs the *programs JoyBox uses*, not the JoyBox shims themselves
> (`master_backup`, `save_game_tool`, …), which come from the project bootstrap.

## Options

| Option | Description |
|--------|-------------|
| `-k, --packages` | Comma-separated package names to install (default: all). Quote names with spaces/dashes, e.g. `"7-Zip,RClone"` |
| `-f, --force` | Force a rebuild: remove each selected package's install directory and reinstall |
| `--clean` | Remove the entire tools root directory before installing (full from-scratch rebuild) |
| `-e, --offline` | Install from the local backup copy instead of downloading |
| `-c, --configure` | Run each package's post-install configuration step |
| `-l, --locker_type` | Locker to auto-back-up downloaded files to: `All` (default), `Local`, `Hetzner`, `Gdrive`, `External` |
| `-s, --skip_autobackup` | Skip the automatic backup of downloaded files |
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Install everything missing

```bash
setup_tools
```

### Install specific tools

```bash
setup_tools -k "7-Zip,RClone,Wine"
```

### Update (force a rebuild)

```bash
setup_tools --force                 # rebuild all tools
setup_tools -f -k "RClone,FFMpeg"   # rebuild just these
```

### Clean from-scratch reinstall

```bash
setup_tools --clean
```

### Offline install from local backups

```bash
setup_tools --offline
```

### Install and configure, skipping the auto-backup

```bash
setup_tools -k Ghidra --configure --skip_autobackup
```

### Preview without changing anything

```bash
setup_tools --pretend_run --verbose
```

## Notes

- `--force` is per-package (only the names you select); `--clean` wipes the whole tools
  root. Use `--force` for an update, `--clean` for a full rebuild.
- Downloaded packages are auto-backed-up to the locker (default `All`) so a later
  `--offline` install can reuse them; disable with `--skip_autobackup`.
- An `~/JoyBox.ini` must exist (the requirement check fails otherwise).

## See Also

- `setup_game_emulators` - Install/update emulators (same flags)
- `setup_game_assets` - Create Pegasus asset symlinks
