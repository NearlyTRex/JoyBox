# Remote Server Services

[← Docs index](../README.md)

What `bootstrap.py -t remote_ubuntu` can put on the server, and how the website and the less
obvious services work. Setting a server up from scratch is in
[Remote Server Setup](../setup/remote-server.md).

Install or reinstall particular services with `--components`:

```bash
# Just web server + SSL + management UI
python3 bootstrap.py -a setup -t remote_ubuntu -s 0 --components nginx certbot cockpit

# Add the WordPress site
python3 bootstrap.py -a setup -t remote_ubuntu -s 0 --components wordpress
```

## Available Components (Server)

| Component | What it does |
|-----------|--------------|
| `config` | Configuration setup |
| `dotfiles` | Dot files installation |
| `aptget` | System packages |
| `flatpak` | Flatpak apps |
| `nginx` | Nginx with config templates |
| `certbot` | Let's Encrypt SSL certs |
| `cockpit` | Server management web UI |
| `wordpress` | WordPress — serves the apex domain |
| `audiobookshelf` | Audiobook streaming |
| `navidrome` | Music streaming |
| `filebrowser` | Web file manager |
| `jenkins` | CI/CD server |
| `kanboard` | Project management |
| `fitlog` | FitLog — personal food and exercise tracker |
| `oscar` | Open OSCAR Server — self-hosted AIM/ICQ |

## Logins

Each app's first login comes from `JoyBox.ini`, so a fresh deploy never shows a setup page that
the first visitor could claim. Passwords can be `op://` references (see
[Secrets](../reference/secrets.md)).

| Component | Settings | Behaviour |
|-----------|----------|-----------|
| `cockpit` | `server_N_user`, `server_N_pass` | Cockpit signs in with the server's own account |
| `wordpress` | `wordpress_admin_user`, `wordpress_admin_pass` | Created by the seed on install |
| `filebrowser` | `filebrowser_admin_user`, `filebrowser_admin_pass` | Synced on every start; the password needs 12 or more characters |
| `kanboard` | `kanboard_admin_user`, `kanboard_admin_pass` | Required. Synced on every deploy; the stock `admin`/`admin` account is renamed to the configured user |
| `jenkins` | `jenkins_admin_user`, `jenkins_admin_pass` | Synced on every start, and the setup wizard is skipped. With no password the wizard runs instead |
| `navidrome` | `navidrome_admin_user`, `navidrome_admin_pass` | Created on the first deploy only; manage it in the app afterwards |
| `audiobookshelf` | `audiobookshelf_admin_user`, `audiobookshelf_admin_pass` | Created on the first deploy only; manage it in the app afterwards |
| `fitlog` | `fitlog_user`, `fitlog_pass` | Created on the first deploy only, which prints the authenticator QR code once |
| `oscar` | `oscar_user`, `oscar_pass` | A screen name, created or its password reset on every deploy |

"Synced" means the ini wins: a password changed in the app is reset on the next deploy. Passwords
are written to the app's `.env` in single quotes, so they cannot contain a single quote or a
newline.

FileBrowser also sits behind the shared htpasswd prompt, so it takes the htpasswd login first and
the app login second. The OSCAR management API uses only the htpasswd login; AIM clients on port
5190 use the screen name.

## The website

WordPress serves the **apex domain**. `www` 301s to it, and both are on the certificate.

Ownership of the apex is handled through an nginx snippet rather than competing `server` blocks:
the `nginx` component installs a static `apex-root.conf`, and `wordpress` replaces it with a
proxy block, restoring the static one on teardown. Two components therefore never claim the same
`server_name`, and re-running either in isolation is safe.

### Seeded content

After the site is healthy, setup runs `Bootstrap/wordpress/seed.sh` inside the official
`wordpress:cli` container. It sets the title, tagline and permalinks, removes the stock "Hello
world!" post and Sample Page, and creates the pages listed at the bottom of the script from the
HTML fragments in `Bootstrap/wordpress/content/`.

The script is idempotent and runs on every setup. Pages are tracked by the post meta key
`_joybox_seed_id`, not by slug or title — so renaming a page in wp-admin does not cause a
duplicate to be created. **Existing pages are left alone**; your edits in wp-admin win over the
repo unless you run with `SEED_OVERWRITE=1`.

To add content, drop a fragment in `content/` and add a `seed_page` line to `seed.sh`. Set
`wordpress_seed_enabled = False` to turn seeding off entirely.

## AIM / OSCAR server

The `oscar` component builds [Open OSCAR Server](https://github.com/mk6i/open-oscar-server) from
a pinned git tag — upstream publishes no container image — and serves classic AIM and ICQ
clients.

Clients connect to `<oscar_subdomain>.<domain>` on port **5190**.

```ini
[UserData.Oscar]
oscar_subdomain = aim
oscar_port_public = 5190
oscar_port_bos = 15190
oscar_port_api = 18080
oscar_log_level = info
oscar_user = myname
oscar_pass = ...
```

`oscar_port_public` is the port clients dial. `oscar_port_bos` and `oscar_port_api` are
host-side loopback ports that nginx proxies to — you rarely need to change them.

### Why nginx fronts a raw TCP port

The container binds to `127.0.0.1` only, and nginx's `stream` module publishes 5190.
**Docker's published ports bypass ufw**, so binding the container to `0.0.0.0` would put the
port on the internet whatever the firewall says. Routing through nginx is what makes
`ufw` actually govern it. The stream config uses a one-hour `proxy_timeout`: an OSCAR session
stays open as long as the user is signed in, so a short timeout would silently drop clients.

### Creating screen names

Accounts are **not** auto-created. `DISABLE_AUTH` is off, so an unknown screen name is rejected
rather than claimed — otherwise anyone reaching port 5190 could take any name, including yours.

`oscar_user` and `oscar_pass` create one screen name on every deploy, or reset its password to
match. Create any others through the management API, which is proxied over HTTPS on the same subdomain
behind the shared `.htpasswd`:

```bash
curl -u <htpasswd-user> -X POST https://aim.example.com/user \
    -H 'Content-Type: application/json' \
    -d '{"screen_name":"myname","password":"..."}'

# List accounts
curl -u <htpasswd-user> https://aim.example.com/user
```

Set up the htpasswd user first with `Bootstrap/scripts/init_htpasswd.sh` if you have not
already.

### Connecting a client

Point the client's server setting at `aim.example.com` port `5190`. The server advertises that
hostname to clients after login, so it must resolve and be reachable from wherever the client
runs — a client that signs in and then hangs is almost always a wrong advertised host.

Pidgin dropped AIM and ICQ after 2.14.2. The `pidgin` component of `local_ubuntu` builds both
plugins from that release against the installed libpurple and puts them in `~/.purple/plugins`, so
Pidgin offers AIM and ICQ again. Run it after `aptget`, which installs `pidgin` and `libpurple-dev`:

```bash
python3 bootstrap.py -a setup -t local_ubuntu --components pidgin
```

In Pidgin, add an AIM account and set the server and port under its Advanced tab.

TOC, WebAPI and legacy ICQ are disabled: TOC is bound to container loopback (the server requires
the setting), the others are switched off.

### Data

Everything — accounts, buddy lists, offline messages — lives in a single SQLite file on the
`oscar_data` volume, captured by `-a backup --components oscar`. The archive is taken from the
live file, so a write in flight could in principle produce a torn copy; for a server this size
the window is negligible, but a backup taken while the service is stopped is strictly safer.

## FitLog

The `fitlog` component builds [FitLog](https://github.com/NearlyTRex/FitLog) at the tag pinned as
`FITLOG_VERSION` in `Shared/joybox/bootstrap/packages/images.py`, and serves it at `<fitlog_subdomain>.<domain>`.

```ini
[UserData.FitLog]
fitlog_subdomain = fit
fitlog_port_http = 8087
fitlog_timezone = America/Los_Angeles
fitlog_pull_minutes = 10
fitlog_catalog_branch = main
fitlog_user = me
fitlog_pass = ...
```

`fitlog_timezone` decides when "today" rolls over, so set it to your own zone.

The food and exercise catalog is a clone of the FitLog repo in the `fitlog_catalog` volume. The
app clones it on first start and pulls `fitlog_catalog_branch` every `fitlog_pull_minutes`, so a
catalog change reaches the server with a push and no redeploy. Code changes need a new FitLog
release and a bump of `FITLOG_VERSION`.

FitLog has one login and no sign-up page. With `fitlog_user` and `fitlog_pass` set, the first
deploy creates it and prints the authenticator QR code to the terminal, once and never to a log
file; enroll it then. Later deploys leave the login alone. Without those settings, create it by
hand after the first deploy. The command prompts for a password and shows the QR code:

```bash
cd ~/apps/fitlog && docker compose exec fitlog fitlog user create <name>
```

`reset-password` and `reset-totp` in place of `create` recover a lost password or authenticator.

### Data

The food log, workout plans, settings and login live in a single SQLite file on the
`fitlog_state` volume, captured by `-a backup --components fitlog`. As with OSCAR, the archive
is taken from the live file.

## Backups

See [Backup and Restore](backup-restore.md). In short:

```bash
python3 bootstrap.py -a backup -t remote_ubuntu -s 0
```

Teardown keeps your data by default — volumes survive and the app directory is renamed rather
than deleted. Pass `--purge-data` to actually destroy it.

## Notes

- Server components use Docker Compose (v2) for isolation.
- Container image versions are pinned in `Shared/joybox/bootstrap/packages/images.py`;
  `--list-images` shows them. See
  [Configuration](../reference/configuration.md#container-image-pins).
- See [Configuration](../reference/configuration.md) for the `[UserData.Servers]`, WordPress, and Cockpit
  keys these commands read.
