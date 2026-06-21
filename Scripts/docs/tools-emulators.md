# Installing & Updating Tools and Emulators

[← Docs index](README.md)

JoyBox installs the third-party **tools** (7-Zip, FFMpeg, RClone, Wine, yt-dlp, store
downloaders, …) and **emulators** (RetroArch, Dolphin, PCSX2, Citra, mGBA, …) that the other
commands depend on. Both are managed the same way, with one command each:

| Command | Manages | Installs into |
|---------|---------|---------------|
| [`setup_tools`](man/setup_tools.md) | CLI helper programs | `[UserData.Dirs] tools_dir` |
| [`setup_game_emulators`](man/setup_game_emulators.md) | Game emulators | `[UserData.Dirs] emulators_dir` |
| [`setup_game_assets`](man/setup_game_assets.md) | Pegasus asset symlinks | (links under the metadata tree) |

> The shims in `~/.local/bin` (`master_backup`, `save_game_tool`, …) are the *JoyBox* commands
> themselves and are installed by the project bootstrap, **not** by `setup_tools`. `setup_tools`
> installs the external programs those commands call.

## Install everything

```bash
setup_tools                 # install all tools that aren't already installed
setup_game_emulators        # install all emulators
```

Both are **idempotent** — a package already present is skipped, so re-running just fills in
what's missing.

## Update / force a rebuild

There's no separate "update" verb; to refresh a package, force a rebuild. `--force` removes the
package's install directory and reinstalls it.

```bash
setup_tools --force                     # rebuild every tool
setup_tools -f -k "RClone,FFMpeg"       # rebuild just these two
setup_game_emulators -f -k RetroArch    # rebuild a single emulator
```

## Install / rebuild specific packages

`-k`/`--packages` takes a comma-separated list of **package names** (quote names with spaces or
dashes). Without `-k`, all packages are processed.

```bash
setup_tools -k "7-Zip,RClone,Wine"
setup_game_emulators -k "Dolphin,PCSX2,Citra"
```

Package names are the display names defined in `Shared/joybox/tools/*.py` and
`Shared/joybox/emulators/*.py` — e.g. tools `7-Zip`, `FFMpeg`, `RClone`, `Wine`, `Pegasus`,
`Legendary`, `Nile`, `YtDlp`; emulators `RetroArch`, `Dolphin`, `PCSX2`, `Citra`,
`mGBA`, `melonDS`, `DuckStation`, `Yuzu`, `Cemu`.

## Clean reinstall

`--clean` wipes the **entire** tools/emulators root directory before installing — use it for a
from-scratch rebuild (heavier than `--force`, which only touches the named packages).

```bash
setup_tools --clean
setup_game_emulators --clean
```

## Offline install & configuration

| Flag | Effect |
|------|--------|
| `-e`, `--offline` | Install from the local backup copy instead of downloading |
| `-c`, `--configure` | Run each package's post-install configuration step after installing |

```bash
setup_tools --offline             # rebuild from local backups, no network
setup_game_emulators --configure  # install and then apply emulator configuration
```

## Auto-backup of downloads

Newly downloaded packages are automatically backed up to a locker so a later `--offline` install
can reuse them. Control this with:

| Flag | Default | Meaning |
|------|---------|---------|
| `-l`, `--locker_type` | `All` | Locker to back the downloads up to (`All`/`Local`/`Hetzner`/`Gdrive`/`External`) |
| `-s`, `--skip_autobackup` | off | Don't back up downloaded files |

```bash
setup_tools -k Ghidra -s                 # install Ghidra, skip the auto-backup
setup_game_emulators -l Local            # back emulator downloads up to Local only
```

## Set up asset symlinks

After your metadata is built, `setup_game_assets` creates the symlinks that point the Pegasus
frontend's asset folders at the locker's artwork. It takes only the common flags.

```bash
setup_game_assets -v
```

## Common flags

All three accept `-v/--verbose`, `-p/--pretend_run`, `-x/--exit_on_failure`, and `--no-preview`.
Add `--pretend_run --verbose` to preview what would be installed or removed.

## Reference

- [`setup_tools`](man/setup_tools.md) — install/update third-party tools
- [`setup_game_emulators`](man/setup_game_emulators.md) — install/update emulators
- [`setup_game_assets`](man/setup_game_assets.md) — create Pegasus asset symlinks
