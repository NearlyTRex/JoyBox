# download_audio_files

Download audio from a curated list of channels for a given genre and back the
results up to a locker.

## Synopsis

```
download_audio_files -g <genre_type> [-c <cookie_source>] [-l <locker_type>] [options]
```

## Description

`download_audio_files` is a **config-driven** audio fetcher. It does not take a
URL on the command line. Instead it iterates a hardcoded list of channels for the
selected genre, downloads each channel's videos as audio (mp3) via `yt-dlp`, and
backs the resulting files up to the chosen locker.

The channel lists live in `Scripts/lib/config/audio.py` as `story_channels` and
`asmr_channels` (each entry is a `{ "name", "url" }` pair). Per channel, the tool:

1. Creates a temporary download directory.
2. Runs `yt-dlp` to extract audio (`--extract-audio --audio-format mp3`,
   `--embed-thumbnail`, `--embed-metadata`), using a per-channel
   download-archive file so already-downloaded videos are skipped on re-runs.
3. Filters the temp directory down to audio files only
   (`.mp3`, `.m4a`, `.wav`, `.flac`, `.ogg`).
4. Backs the audio up to the locker music directory for that genre/channel
   (`backup` with `skip_existing` and `skip_identical`).
5. Cleans up the temporary directory.

Only the **Story** and **ASMR** genres are wired to download logic in the tool's
`if/elif` branches. The other `AudioGenreType` values (Audiobook, Classical,
Game, Radio, Regular, Soundtrack, Therapy) are valid enum values but are **not**
hooked up to any download path, so passing them performs no downloads.

## Options

### Tool Options

| Option | Description |
|--------|-------------|
| `-g, --genre_type` | Genre to download. Allowed: `ASMR`, `Audiobook`, `Classical`, `Game`, `Radio`, `Regular`, `Soundtrack`, `Story`, `Therapy`. Only `ASMR` and `Story` actually trigger downloads. |
| `-c, --cookie_source` | Cookie source for `yt-dlp` (default: `firefox`). A browser name is passed as `--cookies-from-browser`; an existing file path is passed as `--cookies`. |
| `-l, --locker_type` | Locker to back the audio up to (default: `All`). Allowed: `All`, `Local`, `Hetzner`, `Gdrive`, `External`. |

### Common Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-p, --pretend_run` | Dry run without making changes (passes `--simulate` to `yt-dlp`) |
| `-x, --exit_on_failure` | Exit immediately on any error |
| `--no-preview` | Skip the preview confirmation prompt |

## Examples

### Download the Story channels

```bash
download_audio_files -g Story
```

### Download ASMR and back up only to the local locker

```bash
download_audio_files -g ASMR -l Local
```

### Use a Chrome cookie source

```bash
download_audio_files -g Story -c chrome
```

### Use a cookies file instead of a browser

```bash
download_audio_files -g Story -c /path/to/cookies.txt
```

### Dry run

```bash
download_audio_files -g Story -p -v
```

## Notes

- Requires `yt-dlp` to be installed; if it is missing the download fails.
- The per-channel download archive makes re-runs incremental: only new videos
  are fetched, so the tool is safe to run repeatedly to pick up new uploads.
- A `yt-dlp` exit code of 1 with no new files is treated as success (everything
  was already archived); only exit codes greater than 1 are treated as failures.
- Cookies are typically required for channels that gate content; the default
  `firefox` source reads cookies from a local Firefox profile.

## See Also

- `audio_metadata_tool` - Scan, clear, and apply ID3 tags for downloaded audio
- `generate_playlist` - Build `.m3u` playlists from an audio tree
- `master_backup` - Back up the local locker to remote lockers
