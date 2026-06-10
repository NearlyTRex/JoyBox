# Cloud Lockers

[← Docs index](README.md)

Lockers are the storage targets JoyBox backs up to:

- **Local** — `$HOME/Locker`, the authoritative source, unencrypted.
- **Hetzner** — SFTP, a full **encrypted** backup.
- **Gdrive** — Google Drive, plaintext (ROMs excluded).
- **External** — a mounted drive.

Configuration is read from `~/JoyBox.ini`.

## Step 1 — create the rclone remote

A locker is backed by a normal rclone remote; JoyBox calls rclone under the hood.

```bash
rclone config        # add an SFTP remote for Hetzner, a Drive remote for Gdrive, etc.
```

For **Hetzner / any SFTP** remote, add this to the rclone remote config — SFTP shells have no
usable `md5sum`, so without it transfers fail with false "corrupted on transfer" errors:

```ini
disable_hashcheck = true
```

> **Important:** JoyBox does its **own** encryption (the `cryption` module) for encrypted
> lockers — it is *not* rclone crypt. The rclone remote stays plain; encrypted lockers must go
> through `master_backup` / the locker tools, never a raw `rclone copy` (that would upload
> plaintext).

## Step 2 — declare the locker in `~/JoyBox.ini`

Keys live under `[UserData.Share]` and are named `locker_<name>_*`, where `<name>` is the
lowercased locker type (`hetzner`, `gdrive`, `external`).

```ini
[UserData.Share]
# --- Hetzner: full encrypted backup over SFTP ---
locker_hetzner_type          = SFTP            ; SFTP | Drive | WebDAV | B2
locker_hetzner_name          = HetznerBox      ; the rclone remote name from step 1
locker_hetzner_remote_path   = JoyBox          ; path within the remote
locker_hetzner_encrypted     = true            ; JoyBox-side encryption on this locker
; locker_hetzner_excluded_dirs = .recycle_bin/**, *.tmp
; locker_hetzner_mount_flags   = --no-checksum, --fast-list
; locker_hetzner_mount_path    = /mnt/hetzner

# --- Gdrive: plaintext, ROMs excluded ---
locker_gdrive_type           = Drive
locker_gdrive_name           = GdriveBackup
locker_gdrive_remote_path    = /JoyBox
locker_gdrive_encrypted      = false
locker_gdrive_excluded_dirs  = Gaming/Roms/**, Gaming/DLC/**, Gaming/Updates/**

# --- External: a mounted drive ---
locker_external_mount_path   = /mnt/external_drive

primary_remote_locker        = Hetzner         ; default remote for single-remote operations

[UserData.Protection]
locker_passphrase            = your_encryption_passphrase   ; used by encrypted lockers
```

### Recognised keys

All optional unless noted: `_type`, `_name`, `_remote_path`, `_config`, `_token`,
`_mount_flags`, `_mount_path`, `_excluded_dirs`, `_encrypted`, and `_passphrase` (which falls
back to `[UserData.Protection] locker_passphrase`). `primary_remote_locker` selects the default
remote for single-remote operations.

## Step 3 — verify with a dry run

```bash
master_backup --pretend_run --verbose
```

If the source and destinations resolve, you're configured. Continue to [Backups](backups.md).

## Reference

- [`master_backup`](man/master_backup.md) — back up Local → remotes
- [`locker_sync_tool`](man/locker_sync_tool.md) — sync a primary locker to secondaries
- [`rebuild_hash_sidecars`](man/rebuild_hash_sidecars.md) — rebuild a remote's hash sidecar
- [`find_missing_hash_sidecars`](man/find_missing_hash_sidecars.md) — find files missing from the sidecar
