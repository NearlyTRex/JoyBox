# Backup and Restore

[← Docs index](README.md)

Backups of the server's stateful services go to the Hetzner Storage Box, which
`init_storagebox.sh` mounts at `/mnt/storage`.

## Taking a backup

```bash
# Everything that declares backup data
python3 bootstrap.py -a backup -t remote_ubuntu -s 0

# One service
python3 bootstrap.py -a backup -t remote_ubuntu -s 0 --components wordpress
```

A backup sweep does **not** stop at the first failure — every component is attempted and the run
reports at the end, so one broken service cannot silently skip the rest.

## What gets backed up

| Component | Contents |
|-----------|----------|
| `wordpress` | Database dump plus the `wp_data` volume (the whole webroot: uploads, themes, plugins) |
| `kanboard` | `data`, `plugins` and `config` directories |
| `navidrome` | Config volume. The music library is mounted read-only from storage and is not copied |
| `audiobookshelf` | Config volume. Cached metadata artwork is deliberately excluded — it is regenerable and large |
| `filebrowser` | Config volume |
| `oscar` | `oscar_data` volume — the SQLite database holding accounts, buddy lists and offline messages |
| `jenkins` | Nothing yet: `jenkins_home_dir` points at `/mnt/repositories`, which also holds every git repo on the box |

Archiving runs inside a container. `configure_docker_security()` enables `userns-remap`, so files
written by containers are owned by an offset uid the SSH user cannot read directly.

## Layout

```
/mnt/storage/Backups/Wordpress/
├── 20260913_031500/
│   ├── backup_manifest.txt
│   ├── db.sql.gz
│   ├── wp_data.tar.gz
│   └── SHA256SUMS
├── 20260912_031500/
└── latest -> 20260913_031500
```

Timestamps are UTC. A backup is written to `<timestamp>.partial` and renamed on success, so a
half-written backup is never mistaken for a complete one. `backup_keep` (default 7) controls how
many are retained.

Backups are checksummed, and `restore` verifies `SHA256SUMS` before touching anything.

`.env` files are **not** archived — they contain database passwords and the Storage Box is
third-party. They are regenerated from `JoyBox.ini` on the next setup.

## Encryption

Excluding `.env` keeps raw `JoyBox.ini` passwords out of the archives, but the dumps
themselves still carry secrets: WordPress's `wp_options` and user password hashes,
FileBrowser's bcrypt admin hash, OSCAR's account database. Those leave the server
and land on storage you do not control.

Set a recipient to encrypt them:

```ini
[UserData.Backup]
backup_age_recipient = age1...
backup_age_identity = /home/you/.joybox-age.key
```

Generate a pair with `age-keygen -o ~/.joybox-age.key`; it prints the public line
that goes in `backup_age_recipient`.

Archives are then written as `db.sql.gz.age` and `<volume>.tar.gz.age`, encrypted
per-file so one corrupt archive does not cost the set. Checksums cover the encrypted
artifacts. Because this is public-key encryption, the server holds only the public
half — **a compromised box cannot decrypt its own backup history.**

During restore the private key is read from your machine, staged on the server's
`/dev/shm` (RAM, never disk) and removed afterwards, whether the restore succeeds
or fails.

Leaving `backup_age_recipient` empty keeps the old plain-gzip behaviour, and restore
detects `.age` by extension — so archives taken before encryption was enabled keep
restoring unchanged.

> **Store the private key somewhere off-server that you will not lose.** Without it
> every encrypted backup is unrecoverable. There is no recovery path by design.

## Restoring

Restore overwrites live data, so it is deliberately awkward:

```bash
python3 bootstrap.py -a restore -t remote_ubuntu -s 0 \
    --components wordpress --backup-id latest --confirm restore
```

All three are required:

- `--components` — restore refuses to act on everything at once.
- `--backup-id` — a timestamp such as `20260913_031500`, or the literal `latest`.
- `--confirm restore` — typed out. This is deliberately *not* `-f`, which you type reflexively
  during normal setup work.

Add `-p` to dry-run without the confirmation.

Before restoring anything, a `*_prerestore` snapshot of the current state is taken automatically,
and the restore aborts if that snapshot fails. The path is printed so you have an undo point.

## Teardown and data

`teardown` keeps your data by default: containers stop with `docker compose down` (no `-v`, so
named volumes survive) and the app directory is renamed to `<app>.removed-<timestamp>` rather
than deleted.

To actually destroy it:

```bash
python3 bootstrap.py -a teardown -t remote_ubuntu -s 0 --components kanboard --purge-data
```
