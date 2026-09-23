# JoyBox Documentation

## Start here

| I want to… | Guide |
|------------|-------|
| Set up my own computer | [Local Computer Setup](setup/local-computer.md) |
| Set up the website server | [Remote Server Setup](setup/remote-server.md) |
| Set up a machine on my home network | [Homelab Server Setup](setup/homelab-server.md) |
| Rehearse the website server on a VM | [Testing the Remote Server](testing/remote-server.md) |
| Try a homelab image on a VM | [Testing the Homelab Server](testing/homelab-server.md) |

Which VM tool is for which server: [Testing](testing/README.md).

## Remote server

| Page | What it covers |
|------|----------------|
| [Services](remote-server/services.md) | Every component, the website, and the AIM/OSCAR server |
| [Hardening](remote-server/hardening.md) | Loopback-only containers, key-only SSH, encrypted backups |
| [Backup and Restore](remote-server/backup-restore.md) | Backing up and restoring app data to the Storage Box |

## Homelab server

| Page | What it covers |
|------|----------------|
| [Autoinstall Images](homelab-server/autoinstall.md) | Settings, overlays, checksum and signature checks, and what the build does to the image |
| [The LLM Server Image](homelab-server/llm-overlay.md) | The GPU ollama server overlay |

## Everyday use

| Guide | What it covers |
|-------|----------------|
| [Using the Tools](guides/using-the-tools.md) | The flags every command shares, and how games are selected |
| [Tools & Emulators](guides/tools-emulators.md) | Installing the third-party tools and emulators the commands use |
| [Cloud Lockers](guides/cloud-lockers.md) | Setting up remote lockers: the rclone remote and the `~/JoyBox.ini` keys |
| [Locker Backups](guides/locker-backups.md) | Pushing the local locker to remotes with `master_backup`, and hash sidecars |
| [Game Collection](guides/game-collection.md) | Updating game JSON and metadata for store purchases and manually added files |
| [Save Games](guides/save-games.md) | Capturing and archiving game saves |
| [Audio & Music](guides/audio.md) | Downloading, tagging and converting audio, and building playlists |

## Reference

| Page | What it covers |
|------|----------------|
| [Command Reference](reference/man/README.md) | Every command in `Scripts/bin`, generated from its `--help` |
| [Configuration](reference/configuration.md) | `~/JoyBox.ini` and its key settings |
| [Secrets](reference/secrets.md) | Referencing passwords and keys in 1Password instead of the ini |
| [Bootstrap Commands](reference/bootstrap-commands.md) | Everyday `bootstrap.py` commands and flags |
| [Dotfiles](reference/dotfiles.md) | How the shell config is managed, plus backup and capture |
| [Adding Software](reference/adding-software.md) | Adding packages and writing installers |

## Conventions

- Run `bootstrap.py` from the repo root. The JoyBox commands (`master_backup`,
  `build_autoinstall_iso`, …) run from anywhere once set up.
- Add `-p -v` (pretend run, verbose) the first time you run anything.
- Command pages are generated: edit a script's help text and run `build_man_pages`, never the
  page itself.
