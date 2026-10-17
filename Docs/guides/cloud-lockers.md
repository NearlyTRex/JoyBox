# Cloud Lockers

[← Docs index](../README.md)

Lockers are the storage targets JoyBox backs up to:

- **Local** — `$HOME/Locker`, the authoritative source, unencrypted.
- **Hetzner** — SFTP, a full **encrypted** backup.
- **Gdrive** — Google Drive, plaintext (ROMs excluded).
- **External** — a mounted drive.

Configuration is read from `~/JoyBox.ini`.

## Step 1 — keep each remote's credentials in 1Password

A locker is backed by an rclone remote, but there is no `rclone config` step: JoyBox defines
each remote from the locker's settings when it runs rclone, and hands it over in the environment
of that one command (`RCLONE_CONFIG_<NAME>_<OPTION>`). No credential is written to
`rclone.conf`, which only holds a note, or appears on a command line.

The remote's options go in `locker_<name>_config` as a JSON object, kept in 1Password as a
[secret reference](../reference/secrets.md):

- **Hetzner / any SFTP** — `{"host": "u123456.your-storagebox.de", "user": "u123456", "pass": "..."}`.
  The password may be plain or already obscured with `rclone obscure`; JoyBox obscures a plain one
  the way `rclone config create` would. `shell_type = unix` and `disable_hashcheck = true` are
  added for you: SFTP shells have no usable `md5sum`, so without it transfers fail with false
  "corrupted on transfer" errors. The server's host key is checked against `~/.ssh/known_hosts`
  (`known_hosts_file`): the first time a machine uses the locker its key is recorded there, and
  after that a different key is refused, so nothing can pose as the server. Set
  `known_hosts_file` in the config to use a file of your own instead.
- **Google Drive** — a [service account](https://rclone.org/drive/#service-account-support), so
  there is no OAuth token for rclone to refresh and store:
  `{"service_account_credentials": { ...the key JSON... }, "root_folder_id": "<locker folder id>"}`.
  Create the service account in Google Cloud, download its JSON key, and share the locker folder
  with the account's email address. The folder id is the last part of the folder's URL.

A remote name is the locker's `_name`, and may use letters, digits and `_` only. Check one
resolves with `sync_tool -a Init -l <locker>`.

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
locker_hetzner_name          = HetznerBox      ; the rclone remote name
locker_hetzner_config        = op://Private/JoyBox/locker_hetzner_config
locker_hetzner_remote_path   = JoyBox          ; path within the remote
locker_hetzner_encrypted     = true            ; JoyBox-side encryption on this locker
; locker_hetzner_excluded_dirs = .recycle_bin/**, *.tmp
; locker_hetzner_mount_flags   = --no-checksum, --fast-list
; locker_hetzner_mount_path    = /mnt/hetzner

# --- Gdrive: plaintext, ROMs excluded ---
locker_gdrive_type           = Drive
locker_gdrive_name           = GdriveBackup
locker_gdrive_config         = op://Private/JoyBox/locker_gdrive_config
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

If the source and destinations resolve, you're configured. Continue to [Locker Backups](locker-backups.md).

## Reference

- [`master_backup`](../reference/man/master_backup.md) — back up Local → remotes
- [`locker_sync_tool`](../reference/man/locker_sync_tool.md) — sync a primary locker to secondaries
- [`rebuild_hash_sidecars`](../reference/man/rebuild_hash_sidecars.md) — rebuild a remote's hash sidecar
- [`find_missing_hash_sidecars`](../reference/man/find_missing_hash_sidecars.md) — find files missing from the sidecar
