# download_audio_files

Download audio from a curated list of channels for a given genre and back the
results up to a locker.

## Synopsis

```
download_audio_files -g <genre_type> [-c <cookie_source>] [-l <locker_type>] [-o <output_path>] [options]
```

## Description

`download_audio_files` is a **config-driven** audio fetcher. It does not take a
URL on the command line. Instead it iterates a hardcoded list of channels for the
selected genre, downloads each channel's videos as audio (mp3) via `yt-dlp`, and
backs the resulting files up to the chosen locker.

The channel lists live in `Scripts/lib/config/audio.py` as `story_channels` and
`asmr_channels` (each entry is a `{ "name", "url" }` pair). Per channel, the tool:

1. Enumerates the channel's video IDs (`yt-dlp --flat-playlist`) and skips any
   already recorded in the per-channel download-archive file, so re-runs only
   fetch new uploads.
2. Splits the remaining videos into **batches** (`audio_download_batch_size`,
   default 25) and, for each batch, runs `yt-dlp` to extract audio
   (`--extract-audio --audio-format mp3`, `--embed-thumbnail`, `--embed-metadata`).
3. Filters each batch down to audio files only (`.mp3`, `.m4a`, `.wav`, `.flac`,
   `.ogg`) and backs them up to the locker music directory for that genre/channel
   (`backup` with `skip_existing` and `skip_identical`) **before** starting the
   next batch — so audio is uploaded incrementally instead of all at the end.
4. Cleans up the batch's working directory.

By default each batch uses a throwaway temporary directory. With `-o/--output_path`
the per-channel working directory is **persistent and resumable** (see *Resuming*).

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
| `-o, --output_path` | Persistent per-channel working folder (`<output_path>/<channel>`). Makes runs **resumable**: downloaded audio is kept here instead of a throwaway temp dir, and a re-run re-uploads anything an interrupted run left behind. Default: a temp dir. |

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

### Resume into a persistent folder

Keep downloads in a persistent folder so an interrupted run can be resumed (a
re-run with the same `-o` re-uploads anything left behind, then continues):

```bash
download_audio_files -g Story -o ~/audio_resume
```

### Large backlog: stage locally, push remotes separately

For a big first-time pull, stage to the local locker only, then push to the
remotes with `master_backup` (far faster than per-file inline uploads to an
encrypted remote):

```bash
download_audio_files -g Story -o ~/audio_resume -l Local
master_backup -r Hetzner -v
```

### Dry run

```bash
download_audio_files -g Story -p -v
```

## Resuming

Downloads are **batched** (`audio_download_batch_size` in
`Scripts/lib/config/audio.py`, default 25): each batch is downloaded, uploaded,
and cleaned up before the next, so a long channel uploads incrementally rather
than holding everything until the end.

With `-o/--output_path`, each channel works in a persistent
`<output_path>/<channel>` directory that is **not** deleted. On the next run the
tool first re-uploads any audio left there by an interrupted run, then continues
downloading. Without `-o`, interrupting a run discards that batch's temp dir
(the download archive still prevents re-downloading completed videos, but a
completed-yet-unuploaded file would be lost).

## Notes

- Requires `yt-dlp` to be installed; if it is missing the download fails.
- The per-channel download archive makes re-runs incremental: only new videos
  are fetched, so the tool is safe to run repeatedly to pick up new uploads.
- If the channel cannot be enumerated, the tool falls back to downloading the
  whole channel in a single pass.
- A `yt-dlp` exit code of 1 with no new files is treated as success (everything
  was already archived); only exit codes greater than 1 are treated as failures.
- Cookies are typically required for channels that gate content; the default
  `firefox` source reads cookies from a local Firefox profile.
- Uploads to a remote happen file-by-file inline and are **silent without
  `-v`** — for large backlogs prefer `-l Local` plus a separate `master_backup`,
  which batches and encrypts to a staging tree.

## See Also

- `audio_metadata_tool` - Scan, clear, and apply ID3 tags for downloaded audio
- `generate_playlist` - Build `.m3u` playlists from an audio tree
- `master_backup` - Back up the local locker to remote lockers
