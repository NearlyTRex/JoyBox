# login_game_stores

Authenticate with one or more game stores so their purchase lists and metadata can be
retrieved.

## Synopsis

```
login_game_stores [-c <category>] [-s <subcategory>] [-m <generation_mode>] [options]
```

## Description

`login_game_stores` opens a login session for each selected store. A store is chosen by
its category and subcategory — for example `-c Computer -s Steam` selects the Steam
store. If you omit the category or subcategory the tool iterates every store-backed
subcategory and logs in to each one in turn.

The supercategory defaults to `Roms`; you do not need to pass `-u`. Only subcategories
that map to a real store (Steam, Epic Games, GOG, etc.) trigger a login; others are
skipped.

Logging in primes the store session used by `build_game_store_purchases` (to import
your purchase list) and by the metadata/asset tools (to fetch store-hosted data). Run
this first when a store session has expired or before a bulk import.

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

### Log in to Steam

```bash
login_game_stores -c Computer -s Steam
```

### Log in to the Epic Games store

```bash
login_game_stores -c Computer -s "Epic Games"
```

### Log in to every configured store

```bash
login_game_stores
```

## Notes

- The supercategory defaults to `Roms` — there is no need to pass `-u Installs`.
- Subcategories without a backing store are silently skipped.
- Run this before `build_game_store_purchases` if your store session has expired.

## See Also

- `build_game_store_purchases` - Import a store's purchase list into JSON entries
- `build_game_metadata_files` - Build metadata entries (may fetch store data)
- `download_game_metadata_assets` - Download artwork/video assets (may fetch from a store)
