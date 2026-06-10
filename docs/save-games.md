# Save Games

[← Docs index](README.md)

`save_game_tool` captures, restores, and archives game saves. The operation is chosen with
`-a, --action` (default `Pack`).

## Back up saves from a store game (Steam, Epic, …)

For **store** games the saves live in the store's own on-disk folders, not in the locker. Use
`--action Export`: it pulls the *live* save files, archives them to a timestamped zip, and backs
that up to the locker(s).

```bash
# Dry run first — see which Steam saves would be captured
save_game_tool --action Export -c Computer -s Steam --pretend_run --verbose

# Do it for real (backs up to all lockers by default)
save_game_tool --action Export -c Computer -s Steam

# A single game, to one locker only
save_game_tool --action Export -c Computer -s Steam -n "Hollow Knight" -l Local
```

`--action Pack`, by contrast, only re-archives a save directory that is already in the locker —
it won't pull fresh files from the store. So for "grab from Steam → archive → onto backups",
`Export` is the one.

## Other actions

| Action | What it does |
|--------|--------------|
| `Export` | Store games: pull live saves → archive → back up. Non-store games: pack the existing save dir. |
| `Pack` | Re-archive a save directory already in the locker (timestamped, deduplicated). |
| `Unpack` | Extract the latest packed archive back into the live save directory (won't overwrite a non-empty one). |
| `Import` | Non-store games: unpack the latest archive into place. Store games: no-op. |
| `ImportSavePaths` | Store games: derive save paths from packed archives and merge them into the game's JSON. |

## Key flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-a`, `--action` | `Pack` | `Export`, `Pack`, `Unpack`, `Import`, `ImportSavePaths` |
| `-l`, `--locker_type` | `All` | Destination: `All`, `Local`, `Hetzner`, `Gdrive`, `External` (used by `Pack`/`Export`) |
| `-c` / `-s` / `-n` | — | Standard game selection (see [Getting Started](getting-started.md)) |

> Packs are timestamped, so each export produces a new historical archive rather than
> overwriting prior ones. This can be long-running and network-heavy when uploading to
> Hetzner/Gdrive — run it in a terminal rather than backgrounding it.

## Reference

- [`save_game_tool`](../Scripts/docs/man/save_game_tool.md) — full breakdown of every action and flag
