# setup_game_emulators

Install, update, or rebuild the game emulators JoyBox manages.

## Synopsis

```
setup_game_emulators [-k <packages>] [-f] [--clean] [-e] [-c] [options]
```

## Description

`setup_game_emulators` installs the emulators used to run the collection —
e.g. `RetroArch`, `Dolphin`, `PCSX2`, `Citra`, `mGBA`, `melonDS`, `DuckStation`, `Yuzu`,
`Cemu`, and more. Emulators are defined in `Scripts/lib/emulators/*.py`; each knows how to
download, install, and (optionally) configure itself.

The process for each selected emulator:

1. Optionally clean the whole emulators root (`--clean`) or the emulator's own install
   directory (`--force`) first.
2. Install it — online (download) by default, or from the local backup with `--offline`.
3. Optionally run its configuration step (`--configure`).

It is **idempotent**: an emulator already installed is skipped unless you `--force` or
`--clean`. Emulators install under the directory named by `[UserData.Dirs] emulators_dir`
in `~/JoyBox.ini`.

This command shares its interface with `setup_tools`; only the package set and install
root differ.

## Options

| Option | Description |
|--------|-------------|
| `-k, --packages` | Comma-separated emulator names to install (default: all). Quote names with spaces/dashes, e.g. `"FS-UAE,VICE-C64"` |
| `-f, --force` | Force a rebuild: remove each selected emulator's install directory and reinstall |
| `--clean` | Remove the entire emulators root directory before installing |
| `-e, --offline` | Install from the local backup copy instead of downloading |
| `-c, --configure` | Run each emulator's post-install configuration step |
| `-l, --locker_type` | Locker to auto-back-up downloaded files to: `All` (default), `Local`, `Hetzner`, `Gdrive`, `External` |
| `-s, --skip_autobackup` | Skip the automatic backup of downloaded files |
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Install all emulators

```bash
setup_game_emulators
```

### Install specific emulators

```bash
setup_game_emulators -k "Dolphin,PCSX2,Citra"
```

### Update (force a rebuild)

```bash
setup_game_emulators --force                # rebuild all
setup_game_emulators -f -k RetroArch        # rebuild a single emulator
```

### Clean from-scratch reinstall

```bash
setup_game_emulators --clean
```

### Offline install, then configure

```bash
setup_game_emulators --offline --configure
```

### Preview without changing anything

```bash
setup_game_emulators --pretend_run --verbose
```

## Notes

- `--force` is per-emulator (only the names you select); `--clean` wipes the whole
  emulators root. Use `--force` for an update, `--clean` for a full rebuild.
- Downloaded emulators are auto-backed-up to the locker (default `All`) so a later
  `--offline` install can reuse them; disable with `--skip_autobackup`.
- An `~/JoyBox.ini` must exist (the requirement check fails otherwise).

## See Also

- `setup_tools` - Install/update third-party tools (same flags)
- `setup_game_assets` - Create Pegasus asset symlinks
