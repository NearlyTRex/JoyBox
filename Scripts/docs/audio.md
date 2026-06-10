# Audio & Music

[← Docs index](README.md)

Download music / ASMR / stories into the locker, tag it, convert audiobooks, and build
playlists.

## Download audio

`download_audio_files` is **config-driven**, not URL-driven: for the chosen genre it iterates a
channel list baked into `Scripts/lib/config/audio.py`, and for each channel downloads videos as
audio in **batches** (default 25), uploading each batch to the locker before the next — so a long
channel uploads incrementally instead of all at the end.

```bash
# Download all ASMR-channel audio and back it up everywhere
download_audio_files --genre_type ASMR

# Stories, pulling YouTube cookies from Firefox, staged to Local only
download_audio_files --genre_type Story --cookie_source firefox --locker_type Local --verbose
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-g`, `--genre_type` | — | Genre to pull. **Only `ASMR` and `Story` are wired to download logic.** The enum also defines `Audiobook`, `Classical`, `Game`, `Radio`, `Regular`, `Soundtrack`, `Therapy`, but those branches do nothing yet. |
| `-c`, `--cookie_source` | `firefox` | Browser to pull YouTube cookies from |
| `-l`, `--locker_type` | `All` | Where to back up (`All`/`Local`/`Hetzner`/`Gdrive`/`External`) |
| `-o`, `--output_path` | temp dir | Persistent per-channel folder. Makes runs **resumable** — keeps downloads on disk and re-uploads anything an interrupted run left behind. |

### Resuming & large backlogs

Pass `-o` to keep downloads in a persistent folder so an interrupted run can be picked up where
it left off:

```bash
download_audio_files --genre_type Story -o ~/audio_resume
```

For a big first-time pull, stage to **Local** only and push to the remotes separately —
`master_backup` batches and encrypts far more efficiently than the tool's per-file inline upload
(which is also silent without `-v`):

```bash
download_audio_files --genre_type Story -o ~/audio_resume -l Local
master_backup -r Hetzner -v
```

Reference: [`download_audio_files`](man/download_audio_files.md).

## Tag the downloads

```bash
# Extract metadata into JSON sidecars, then write those tags into the audio files
audio_metadata_tool --action Tag   --genre ASMR -v
audio_metadata_tool --action Apply --genre ASMR -v
```

Actions are `Tag` (extract → JSON), `Apply` (JSON → file tags), and `Clear` (strip tags; add
`--preserve_artwork` to keep cover art). Narrow with `-b`/`--album` or `-r`/`--artist`.
Reference: [`audio_metadata_tool`](man/audio_metadata_tool.md).

## Convert Audible audiobooks

```bash
# AAX/AA -> M4A (needs your activation bytes)
audio_conversion_tool --action AaxToM4a -i ~/audiobooks/book.aax -k 1a2b3c4d
```

Activation bytes resolve from `-k`/`--activation_bytes`, `-f`/`--authcode_file`, the
`AUDIBLE_ACTIVATION_BYTES` env var, or `~/.audible_authcode`. Reference:
[`audio_conversion_tool`](man/audio_conversion_tool.md).

## Build playlists

```bash
# .m3u playlists across a folder tree
generate_playlist -i ~/Locker/Music/ASMR -f .mp3
```

Reference: [`generate_playlist`](man/generate_playlist.md).

## Reference

| Command | Purpose |
|---------|---------|
| [`download_audio_files`](man/download_audio_files.md) | Download audio from curated channels by genre |
| [`audio_metadata_tool`](man/audio_metadata_tool.md) | Tag / apply / clear audio metadata |
| [`audio_conversion_tool`](man/audio_conversion_tool.md) | Convert Audible AAX/AA → M4A |
| [`generate_playlist`](man/generate_playlist.md) | Generate `.m3u` playlists from a tree |
