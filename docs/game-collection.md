# Game Collection (JSON + Metadata)

[← Docs index](README.md)

Every game in the locker has a JSON entry plus generated metadata (artwork, screenshots, the
Pegasus metadata files, and published HTML). There are two ways games enter the collection, and
each has its own workflow.

## A. Store purchases (Steam / GOG / Epic / Amazon / Humble / Itchio / …)

Pull the purchase list from the store, then build JSON + metadata. `-c`/`-s` pick the store.

```bash
# (first time / when the session expires) log in to the store
login_game_stores -c Computer -s Steam -v

# import purchases and create/update their JSON entries
build_game_store_purchases -c Computer -s Steam -v

# build the metadata files, then fetch box art / screenshots / videos
build_game_metadata_files     -c Computer -s Steam -v
download_game_metadata_assets -c Computer -s Steam -e -v   # -e skips assets already downloaded
```

Process every store at once by dropping `-s` (and `-c`).

References: [`login_game_stores`](../Scripts/docs/man/login_game_stores.md) ·
[`build_game_store_purchases`](../Scripts/docs/man/build_game_store_purchases.md).

## B. Files moved manually into the locker (ROMs, disc images, …)

After dropping files into the right `…/Roms/<Category>/<Subcategory>/` folder, regenerate the
JSON, metadata, hashes, and assets.

### All-in-one wrapper

```bash
# scan one subcategory: builds JSON + metadata, downloads assets (-a), loads manifest (-m)
scan_game_files -c Nintendo -s "Nintendo 64" -a -m -v
```

> **Note:** `scan_game_files` takes **comma-separated lists** —
> `-c`/`--categories` and `-s`/`--subcategories` (e.g. `-c Nintendo,Sony
> -s "Nintendo 64,Sony PlayStation 2"`). This differs from the single-value `-c`/`-s` used by
> the individual tools below. See [`scan_game_files`](../Scripts/docs/man/scan_game_files.md).

### Or the individual steps (more control)

```bash
build_game_json_files         -c Nintendo -s "Nintendo 64" -v   # scan files -> JSON entries
build_game_metadata_files     -c Nintendo -s "Nintendo 64" -v   # JSON -> metadata files
build_game_hash_files         -c Nintendo -s "Nintendo 64" -v   # checksum sidecars for files
download_game_metadata_assets -c Nintendo -s "Nintendo 64" -e -v
```

Target a single title with `-n`:

```bash
build_game_json_files     -c Nintendo -s "Nintendo 64" -n "Super Mario 64" -v
build_game_metadata_files -c Nintendo -s "Nintendo 64" -n "Super Mario 64" -v
```

## Finishing up: sort and publish

After updating metadata you can normalize it and render the browsable HTML:

```bash
sort_game_metadata -v
publish_game_metadata_files -v
```

References: [`sort_game_metadata`](../Scripts/docs/man/sort_game_metadata.md) ·
[`publish_game_metadata_files`](../Scripts/docs/man/publish_game_metadata_files.md).

## Reference

| Command | Purpose |
|---------|---------|
| [`login_game_stores`](../Scripts/docs/man/login_game_stores.md) | Authenticate with a game store |
| [`build_game_store_purchases`](../Scripts/docs/man/build_game_store_purchases.md) | Import a store's purchase list into JSON entries |
| [`build_game_json_files`](../Scripts/docs/man/build_game_json_files.md) | Build JSON entries from files in a locker |
| [`build_game_metadata_files`](../Scripts/docs/man/build_game_metadata_files.md) | Build metadata entries from JSON |
| [`build_game_hash_files`](../Scripts/docs/man/build_game_hash_files.md) | Record file hashes for game files |
| [`download_game_metadata_assets`](../Scripts/docs/man/download_game_metadata_assets.md) | Download artwork / video assets |
| [`scan_game_files`](../Scripts/docs/man/scan_game_files.md) | Run the whole pipeline end to end |
| [`sort_game_metadata`](../Scripts/docs/man/sort_game_metadata.md) | Normalize metadata files |
| [`publish_game_metadata_files`](../Scripts/docs/man/publish_game_metadata_files.md) | Render metadata to HTML |
