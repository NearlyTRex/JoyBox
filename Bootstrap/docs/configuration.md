# Configuration

[← Docs index](README.md)

The first `setup` run creates `~/JoyBox.ini` from the platform defaults if it doesn't exist yet.
After that you edit it directly. Settings with an empty default are written commented out —
uncomment them to set a value.

To point at a config file somewhere other than `~/JoyBox.ini`, pass `-c /path/to/JoyBox.ini`.

> A missing key is **not** silently defaulted. Installers that need a value refuse to run and
> name the key, rather than rendering `None` into a config file.

## Servers

```ini
[UserData.Servers]
domain_name = example.com
domain_contact = me@example.com
server_0_host = myserver.com
server_0_port = 22
server_0_user = myuser
server_0_pass = ...
```

Servers are numbered (`server_0_*`, `server_1_*`, …); the number is what you pass to `-s` when
targeting `remote_ubuntu`. See [Web Server Setup](server-setup.md).

## The website

WordPress serves the **apex domain** (`domain_name`). The `wordpress_subdomain` host redirects
to it with a 301, so `www.example.com` sends visitors to `example.com`.

```ini
[UserData.Wordpress]
wordpress_subdomain = www
wordpress_port_http = 8080
wordpress_db_user = wpuser
wordpress_db_pass = ...
wordpress_db_name = wpdatabase
wordpress_db_root_pass = ...
wordpress_site_title = My Site
wordpress_site_tagline = Something short
wordpress_admin_user = admin
wordpress_admin_pass = ...
wordpress_admin_email = me@example.com
wordpress_seed_enabled = True
```

`wordpress_seed_enabled` controls whether the repo-tracked seed script runs after setup. See
[Web Server Setup](server-setup.md#the-website) for what it does.

## Other services

Each service takes a subdomain and an HTTP port:

```ini
[UserData.Cockpit]
cockpit_subdomain = admin
cockpit_port_http = 9090
```

The same shape applies to `UserData.Kanboard`, `UserData.Navidrome`, `UserData.Audiobookshelf`,
`UserData.FileBrowser`, `UserData.Jenkins` and `UserData.Ghidra`.

## Backups

```ini
[UserData.Backup]
backup_root = /mnt/storage/Backups
backup_keep = 7
```

`backup_root` defaults to the Hetzner Storage Box mount. `backup_keep` is how many timestamped
backups to retain per app; older ones are pruned. See [Backup and Restore](backup.md).

## Container image pins

Image versions are pinned centrally in `Bootstrap/packages/images.py` — that is the file to edit
to move an app to a new version. `[UserData.Images]` exists only to override a pin on one
server, for example while migrating:

```ini
[UserData.Images]
wordpress_db_image = mariadb:11.4
```

Run `python3 bootstrap.py -t remote_ubuntu --list-images` to see every pin and any override.
