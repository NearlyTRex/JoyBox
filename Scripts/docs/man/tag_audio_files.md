# tag_audio_files

Tag audio files with the right per-genre defaults and apply them in a single run,
so you don't have to remember the flags for each genre.

## Synopsis

```
tag_audio_files [-g <genre>] [-b <album>] [-r <artist>] [options]
```

## Description

`tag_audio_files` is a convenience wrapper over `audio_metadata_tool` that bakes in
the settings you always use, then runs the two-step **Tag → Apply** flow for you.
For each genre it processes, it:

1. **Tags** — scans each album's audio files and extracts their tags into a JSON
   metadata file, always excluding comment frames and always forcing the `genre`
   tag to the genre folder's name.
2. **Applies** — writes those tags back into the audio files (unless `--no_apply`
   is given).

The only genre-specific behavior is track numbering: genres downloaded from
YouTube (via `download_audio_files`) carry bogus, uniform track numbers, so their
tracks are renumbered by file index. Which genres get this is controlled by
`config.audio_track_index_genres` (currently **ASMR** and **Story**); every other
genre keeps its existing track numbers.

Album discovery works exactly like `audio_metadata_tool`: albums are found under
the genre's music directory, an `artist/album` structure is detected automatically,
and if no `--genre` is given, **every** genre with albums is processed in turn.

This is the everyday entrypoint; reach for `audio_metadata_tool` when you need
finer control (e.g. `Clear`, tagging without the genre defaults, or overriding the
per-genre track-number policy).

## Options

### Selection

| Option | Description |
|--------|-------------|
| `-g, --genre` | Music genre directory. Allowed: `ASMR`, `Audiobook`, `Classical`, `Game`, `Radio`, `Regular`, `Soundtrack`, `Story`, `Therapy`. **If omitted, every genre with albums is processed** in turn. |
| `-b, --album` | Specific album name to process (if omitted, all albums under the genre are processed) |
| `-r, --artist` | Specific artist name, for albums stored under an `artist/album` structure |

### Behavior Flags

| Option | Description |
|--------|-------------|
| `--set <field>=<value>` | Force an **extra** curated tag to a fixed value on every track (e.g. `album_artist`). Repeatable. The `genre` tag is always set automatically; use this for anything else. |
| `--clear_existing` | Clear existing tags before writing the new ones during the apply step |
| `--no_apply` | Build the JSON metadata files only; do not write tags back to the audio files |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the preview confirmation prompt |

## Examples

### Tag and apply a single genre

```bash
# Excludes comments, forces genre=Story, and (because Story is a YouTube genre)
# renumbers tracks by file index — all automatically.
tag_audio_files -g Story
```

### Tag and apply the whole library

```bash
tag_audio_files --no-preview
```

### Tag and apply one album

```bash
tag_audio_files -g Regular -b "Some Album"
```

### Force an extra field on top of the defaults

```bash
tag_audio_files -g Soundtrack --set album_artist="Various Artists"
```

### Build the JSON only, without touching the audio files

```bash
tag_audio_files -g ASMR --no_apply
```

## Notes

- Equivalent long form for `tag_audio_files -g Story`:

  ```bash
  audio_metadata_tool -a Tag  -g Story --exclude_comments --set genre=Story \
    --use_index_for_track_number
  audio_metadata_tool -a Apply -g Story
  ```

- The per-genre track-index policy lives in `config.audio_track_index_genres`. Add
  or remove a genre there to change which genres get `--use_index_for_track_number`.
- `--set genre=...` is redundant — the genre is always forced to the genre folder.
  Use `--set` only for additional fields; each must be one of the curated tags
  (`title`, `artist`, `album`, `year`, `genre`, `album_artist`, `track_number`,
  `disc_number`, `bpm`, `key`, `conductor`).

## See Also

- `audio_metadata_tool` - Lower-level Tag/Clear/Apply with full control
- `download_audio_files` - Download audio into the locker music tree
- `generate_playlist` - Build `.m3u` playlists from an audio tree
