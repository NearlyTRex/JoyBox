# save_game_tool

Pack, unpack, import, or export game save data and back it up to a locker.

## Synopsis

```
save_game_tool [-a <action>] [-c <category>] [-s <subcategory>] [-n <game_name>] [-l <locker_type>] [options]
```

## Description

`save_game_tool` manages game save archives. The operation it performs is selected
with `-a, --action` (default `Pack`). Games are selected with the standard category /
subcategory / name flags; if you omit a selector, the tool iterates every matching
game that has a JSON entry.

The available actions are:

- **Pack** (default) — Re-archive a save directory that already lives in the locker.
  The save folder is zipped to a temporary archive, validated, deduplicated against
  existing archives (skipped if an identical one is already packed), then written as a
  timestamped zip (`<game> _<timestamp>.zip`) and backed up to the locker via
  `-l, --locker_type`. For `Computer` games, `Wine` and `Sandboxie` save subtrees are
  excluded from the archive.
- **Unpack** — Extract the latest packed save archive from the locker back into the
  live save directory. Skips if the destination already contains files.
- **Export** — For **store** games (Steam, Epic, etc.), this pulls the *live* save
  files straight from the store's on-disk save paths, copies them into a temporary
  tree, then packs that into a timestamped zip and backs it up to the locker
  (`-l, --locker_type`). For non-store games, Export simply packs the existing save
  directory. This is the action to use to capture fresh saves from an installed store
  game.
- **Import** — For non-store games, unpack the latest archive into the live save
  directory (no-op if nothing to unpack). For store games this is currently a no-op.
- **ImportSavePaths** — For store games, inspect the packed save archives, derive the
  tokenized save paths from their contents, merge them into the game's JSON entry, and
  write the updated JSON. For non-store games this is a no-op.

A preview of the games to be processed is shown before any work is done unless
`--no-preview` is given.

Use this tool to capture, restore, or archive game saves, and to keep store save-path
metadata in sync.

## Options

### Action

| Option | Description |
|--------|-------------|
| `-a, --action` | `Pack` (default), `Unpack`, `Import`, `Export`, `ImportSavePaths` |

### Game Selection

| Option | Description |
|--------|-------------|
| `-c, --game_category` | Category: `Computer`, `Microsoft`, `Nintendo`, `Other`, `Sony` |
| `-s, --game_subcategory` | Subcategory/platform (e.g., `Steam`, `Epic Games`, `Nintendo Switch`) |
| `-n, --game_name` | Name of a specific game (optional - if omitted, processes all matching games) |

### Input/Output

| Option | Description |
|--------|-------------|
| `-i, --input_path` | Input path |
| `-l, --locker_type` | Backup destination locker: `All` (default), `Local`, `Hetzner`, `Gdrive`, `External` (used by `Pack` and `Export`) |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Export live saves from a Steam game to the locker

Pull the current on-disk save files for a Steam game, archive them, and back up:

```bash
save_game_tool -a Export -c Computer -s Steam -n "Hades (World)" -l Local
```

### Pack an existing save directory

```bash
save_game_tool -a Pack -c Nintendo -s "Nintendo Switch" -n "Game Name" -l Local
```

### Unpack the latest save archive back into place

```bash
save_game_tool -a Unpack -c Computer -s Steam -n "Hades (World)"
```

### Import save paths for all Steam games

Scan packed save archives and update each Steam JSON entry with derived save paths:

```bash
save_game_tool -a ImportSavePaths -c Computer -s Steam
```

### Export saves for every store game (dry run)

```bash
save_game_tool -a Export -p -v --no-preview
```

## Notes

- `Pack` only re-archives a save directory; it does not pull fresh files from a store.
  To capture new saves from an installed store game, use `Export`.
- Packing is deduplicated: if an identical archive already exists in the locker, the
  pack is skipped.
- Packed saves are timestamped, so each pack/export produces a new historical archive
  rather than overwriting prior ones.
- `Unpack`/`Import` will not overwrite a live save directory that already has files.

## See Also

- `build_game_store_purchases` - Import store purchase lists into JSON entries
- `login_game_stores` - Authenticate with a game store
- `build_game_metadata_files` - Build metadata entries for games
