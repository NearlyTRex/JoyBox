# Man Pages

Full per-command reference for JoyBox Scripts tools. For task-oriented walkthroughs ("how do I
back up my saves?"), see the [documentation guides](../../../docs/README.md).

## Backups & Lockers

| Tool | Description |
|------|-------------|
| [master_backup](master_backup.md) | Back up the local locker (authoritative) to remote lockers in one confirm-and-go run |
| [locker_sync_tool](locker_sync_tool.md) | Interactively sync a primary locker to one or more secondary lockers using hash maps |
| [rebuild_hash_sidecars](rebuild_hash_sidecars.md) | Rebuild the hash sidecar database on a remote locker from local content |
| [find_missing_hash_sidecars](find_missing_hash_sidecars.md) | List files present on a remote locker but missing from its hash sidecar database |
| [sync_tool](sync_tool.md) | Synchronize files between local storage and remote lockers |
| [backup_tool](backup_tool.md) | Backup files with optional encryption/decryption |
| [upload_game_files](upload_game_files.md) | Encrypt and upload game files to a remote locker |
| [crypt_tool](crypt_tool.md) | Encrypt or decrypt files in place |

## Game Collection

| Tool | Description |
|------|-------------|
| [login_game_stores](login_game_stores.md) | Authenticate with one or more game stores so their purchase lists and metadata can be retrieved |
| [build_game_store_purchases](build_game_store_purchases.md) | Import a store's purchase list and create or update JSON entries for each owned game |
| [build_game_json_files](build_game_json_files.md) | Build JSON metadata files for games in a locker |
| [build_game_metadata_files](build_game_metadata_files.md) | Build Pegasus metadata entries for games from their JSON data |
| [build_game_hash_files](build_game_hash_files.md) | Compute and record file hashes for game files in a locker |
| [download_game_metadata_assets](download_game_metadata_assets.md) | Download artwork and video assets for games and back them up to a locker |
| [scan_game_files](scan_game_files.md) | Run the full metadata pipeline: store purchases, JSON, metadata entries, optional assets, and HTML publishing |
| [sort_game_metadata](sort_game_metadata.md) | Normalize every Pegasus game metadata file by re-importing and re-exporting it in sorted order |
| [publish_game_metadata_files](publish_game_metadata_files.md) | Render the game metadata into browsable HTML pages, one per category |

## Save Games

| Tool | Description |
|------|-------------|
| [save_game_tool](save_game_tool.md) | Pack, unpack, import, or export game save data and back it up to a locker |

## Audio & Music

| Tool | Description |
|------|-------------|
| [download_audio_files](download_audio_files.md) | Download audio from a curated list of channels for a given genre and back the results up to a locker |
| [audio_metadata_tool](audio_metadata_tool.md) | Scan, clear, and apply ID3 tags for albums in a locker's music tree, using JSON sidecar files as the source of truth |
| [audio_conversion_tool](audio_conversion_tool.md) | Convert Audible AAX/AA audiobooks to M4A by decrypting them with activation bytes via FFMpeg |
| [generate_playlist](generate_playlist.md) | Generate `.m3u` playlists from a directory tree of media files |

## Setup & Installation

| Tool | Description |
|------|-------------|
| [setup_tools](setup_tools.md) | Install, update, or rebuild the third-party tools JoyBox depends on |
| [setup_game_emulators](setup_game_emulators.md) | Install, update, or rebuild the game emulators JoyBox manages |
| [setup_game_assets](setup_game_assets.md) | Create the asset symlinks that point the Pegasus frontend at the locker's artwork |

## Other

| Tool | Description |
|------|-------------|
| [claude_tool](claude_tool.md) | Process files in bulk using Claude AI |
