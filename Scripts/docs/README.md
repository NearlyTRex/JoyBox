# JoyBox Documentation

Task-oriented guides for the everyday JoyBox workflows. Each guide explains *how to do a
thing*; for the full breakdown of any individual command, follow the **manpage** link in the
guide (manpages live in [`man/`](man/README.md)).

New to the tools? Start with **[Getting Started](getting-started.md)**.

## Contents

| Guide | What it covers |
|-------|----------------|
| [Getting Started](getting-started.md) | Installing the shims, the flags every tool shares, and how games are selected (super/category/subcategory/name). |
| [Tools & Emulators](tools-emulators.md) | Installing and updating the third-party tools and emulators JoyBox depends on, plus asset symlinks. |
| [Cloud Lockers](cloud-lockers.md) | Setting up remote lockers (Hetzner / Gdrive / External): the rclone remote and the `~/JoyBox.ini` keys. |
| [Backups](backups.md) | Pushing Local → remotes with `master_backup`, hash sidecars, and lower-level sync. |
| [Game Collection](game-collection.md) | Updating game JSON + metadata — for store purchases and for files moved manually into the locker. |
| [Save Games](save-games.md) | Capturing and archiving game saves (Steam and other store games) to your backups. |
| [Audio & Music](audio.md) | Downloading music / ASMR / stories, tagging, converting audiobooks, and building playlists. |

## Reference

- **[Manpage index](man/README.md)** — full per-command reference for every documented tool.

## Conventions used in these guides

- Commands are the installed shims in `~/.local/bin` (run `setup_tools` to install/update them).
- Every example is copy-pasteable. Add `--pretend_run --verbose` the first time you run anything.
- Enum values (categories, lockers, actions) are the display strings from
  `Shared/joybox/config/`; quote any value containing a space (e.g. `"Nintendo 64"`).
