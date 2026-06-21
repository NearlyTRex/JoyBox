# JoyBox Scripts

A collection of CLI tools for managing a game/media locker and backing it up to local and cloud
storage. The tools install as thin shims in `~/.local/bin`; the behaviour lives in
`Shared/joybox`, and each `Scripts/bin/*.py` file is just a wrapper.

## Quickstart

```bash
setup_tools              # install or refresh all shims into ~/.local/bin
setup_tools -f           # force a rebuild
```

Make sure `~/.local/bin` is on your `PATH`. Add `--pretend_run --verbose` to any command the
first time you run it to see what would happen without changing anything.

New to the tools? Start with **[Getting Started](docs/getting-started.md)**.

## Documentation

| Guide | What it covers |
|-------|----------------|
| [Getting Started](docs/getting-started.md) | Installing the shims, the flags every tool shares, and how games are selected. |
| [Tools & Emulators](docs/tools-emulators.md) | Installing and updating the third-party tools and emulators JoyBox depends on, plus asset symlinks. |
| [Cloud Lockers](docs/cloud-lockers.md) | Setting up remote lockers (Hetzner / Gdrive / External): the rclone remote and `~/JoyBox.ini` keys. |
| [Backups](docs/backups.md) | Pushing Local → remotes with `master_backup`, hash sidecars, and lower-level sync. |
| [Game Collection](docs/game-collection.md) | Updating game JSON + metadata — for store purchases and for files moved manually into the locker. |
| [Save Games](docs/save-games.md) | Capturing and archiving game saves (Steam and other store games) to your backups. |
| [Audio & Music](docs/audio.md) | Downloading music / ASMR / stories, tagging, converting audiobooks, and building playlists. |

- **Full docs index:** [`docs/README.md`](docs/README.md)
- **Manpage index:** [`docs/man/README.md`](docs/man/README.md) — full per-command reference for every documented tool.
