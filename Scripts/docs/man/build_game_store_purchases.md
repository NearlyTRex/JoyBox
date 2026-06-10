# build_game_store_purchases

Import a store's purchase list and create or update JSON entries for each owned game.

## Synopsis

```
build_game_store_purchases [-c <category>] [-s <subcategory>] [-m <generation_mode>] [options]
```

## Description

`build_game_store_purchases` retrieves the list of games you own from a store and
reconciles it against your JSON metadata. A store is selected by category and
subcategory — for example `-c Computer -s Steam`. Omitting a selector iterates every
store-backed subcategory. The supercategory defaults to `Roms` (no `-u` needed).

For each selected store the tool runs two phases:

1. **Import** — Fetches the latest purchases from the store. For each purchase that is
   not already represented by a JSON file and is not on the store's ignore list, it
   prompts you (`y` to import, `n` to skip, `i` to ignore permanently). On import it
   asks for an entry name, creates the game's JSON file seeded with the store purchase
   data, and creates a matching metadata entry (including the store URL when available).
2. **Update** — For purchases that already match an existing JSON file, it refreshes
   that JSON file from the store and updates the game's downloadable metadata fields.

A preview of the categories to process is shown first unless `--no-preview` is given.

Use this after a `login_game_stores` session to pull newly purchased games into your
collection and refresh existing entries.

## Options

### Game Selection

| Option | Description |
|--------|-------------|
| `-u, --game_supercategory` | Supercategory (default: `Roms`) |
| `-c, --game_category` | Category: `Computer`, `Microsoft`, `Nintendo`, `Other`, `Sony` |
| `-s, --game_subcategory` | Store subcategory (e.g., `Steam`, `Epic Games`, `GOG`) |

### Generation Mode

| Option | Description |
|--------|-------------|
| `-m, --generation_mode` | `Standard` (default) or `Custom` |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the confirmation prompt |

## Examples

### Import Steam purchases

```bash
build_game_store_purchases -c Computer -s Steam
```

### Import Epic Games purchases

```bash
build_game_store_purchases -c Computer -s "Epic Games"
```

### Reconcile purchases across all stores

```bash
build_game_store_purchases
```

## Notes

- The import phase is interactive: each new purchase prompts for import / skip / ignore,
  then for the entry name.
- Choosing ignore (`i`) records the purchase in the store's ignore list so it is not
  offered again on future runs.
- The supercategory defaults to `Roms` — there is no need to pass `-u Installs`.
- Log in first with `login_game_stores` so the store session can return your purchases.

## See Also

- `login_game_stores` - Authenticate with a store before importing purchases
- `build_game_json_files` - Build/refresh JSON metadata from locker files
- `build_game_metadata_files` - Build metadata entries from JSON data
