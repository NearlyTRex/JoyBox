# Using the Tools

[← Docs index](../README.md)

JoyBox's commands manage a game and media locker and back it up to local and cloud storage. Each
one is a shim in `~/.joybox/bin` that runs the matching `Scripts/bin/*.py` wrapper; the behaviour
lives in `Shared/joybox`. Installing and rebuilding the shims is covered in
[Local Computer Setup](../setup/local-computer.md#the-joybox-commands), and every command has a
page in the [command reference](../reference/man/README.md) — the same text `<command> -h` prints.

## Flags every tool shares

`add_common_arguments` gives almost every command the same four flags:

| Flag | Meaning |
|------|---------|
| `-v`, `--verbose` | Verbose logging |
| `-p`, `--pretend_run` | Dry run — show what would happen, change nothing |
| `-x`, `--exit_on_failure` | Stop on the first error instead of skipping |
| `--no-preview` | Skip the confirmation prompt (for unattended runs) |

> **Tip:** add `--pretend_run --verbose` to any command the first time you run it.

## Selecting games

Most game tools take the same selection flags. Values are the display strings from
`Shared/joybox/config/categories.py` — quote any with spaces.

| Flag | Meaning | Examples |
|------|---------|----------|
| `-u`, `--game_supercategory` | Supercategory (default `Roms`) | `Roms`, `DLC`, `Updates`, `Saves`, `Installs` |
| `-c`, `--game_category` | Category | `Computer`, `Nintendo`, `Sony`, `Microsoft`, `Other` |
| `-s`, `--game_subcategory` | Subcategory / platform | `Steam`, `GOG`, `Epic Games`, `Nintendo 64`, `Sony PlayStation 2` |
| `-n`, `--game_name` | A single game (omit = all in the subcategory) | `"Hollow Knight"` |

Omitting a selector means "all matching games". A few tools (notably
[`scan_game_files`](../reference/man/scan_game_files.md)) instead take **comma-separated
lists** via `-c/--categories` and `-s/--subcategories` — the guide and manpage call that out.

### Store subcategories (under `Computer`)

`Amazon Games`, `Disc`, `Epic Games`, `GOG`, `Humble Bundle`, `Itchio`, `Legacy Games`,
`Puppet Combo`, `Red Candle`, `Square Enix`, `Steam`, `Zoom`.

### Lockers

`Local` (`$HOME/Locker`, authoritative, unencrypted), `Hetzner` (SFTP, encrypted), `Gdrive`
(Drive, plaintext), `External` (mounted drive), and `All`. See
[Cloud Lockers](cloud-lockers.md) to configure the remotes.

## Where to go next

- [Tools & Emulators](tools-emulators.md) — install the programs the commands rely on.
- [Cloud Lockers](cloud-lockers.md) — set up your remotes first.
- [Locker Backups](locker-backups.md) — push everything to the cloud.
- [Game Collection](game-collection.md) · [Save Games](save-games.md) · [Audio & Music](audio.md)
