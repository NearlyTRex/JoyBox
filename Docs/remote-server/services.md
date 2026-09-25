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
| `githooks` | Activate the repo's git hooks (secret-scanning pre-commit) |
| `python` | Python venv + pip packages |
| `wrappers` | Script wrappers |
| `aptget` | System packages |
| `awscli` | AWS CLI |
| `flatpak` | Flatpak apps |
| `nginx` | Nginx with config templates |
| `certbot` | Let's Encrypt SSL certs |
| `node` | Global npm packages (ccusage) |
| `claude` | Claude Code CLI |
| `cockpit` | Server management web UI |
| `wordpress` | WordPress — serves the apex domain |
| `audiobookshelf` | Audiobook streaming |
| `navidrome` | Music streaming |
| `filebrowser` | Web file manager |
| `jenkins` | CI/CD server |
| `kanboard` | Project management |
| `fitlog` | FitLog — personal food and exercise tracker |
| `gh` | GitHub CLI (adds repo) |
| `ollama` | Ollama local LLM runtime |
| `oscar` | Open OSCAR Server — self-hosted AIM/ICQ |

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

Create accounts through the management API, which is proxied over HTTPS on the same subdomain
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

TOC, WebAPI and legacy ICQ are disabled: TOC is bound to container loopback (the server requires
the setting), the others are switched off.

### Data

Everything — accounts, buddy lists, offline messages — lives in a single SQLite file on the
`oscar_data` volume, captured by `-a backup --components oscar`. The archive is taken from the
live file, so a write in flight could in principle produce a torn copy; for a server this size
the window is negligible, but a backup taken while the service is stopped is strictly safer.

## FitLog

The `fitlog` component builds [FitLog](https://github.com/NearlyTRex/FitLog) at the tag pinned as
`FITLOG_VERSION` in `Bootstrap/packages/images.py`, and serves it at `<fitlog_subdomain>.<domain>`.

```ini
[UserData.FitLog]
fitlog_subdomain = fit
fitlog_port_http = 8087
fitlog_timezone = America/Los_Angeles
fitlog_pull_minutes = 10
fitlog_catalog_branch = main
```

`fitlog_timezone` decides when "today" rolls over, so set it to your own zone.

The food and exercise catalog is a clone of the FitLog repo in the `fitlog_catalog` volume. The
app clones it on first start and pulls `fitlog_catalog_branch` every `fitlog_pull_minutes`, so a
catalog change reaches the server with a push and no redeploy. Code changes need a new FitLog
release and a bump of `FITLOG_VERSION`.

FitLog has one login and no sign-up page. Create it once after the first deploy. The command
prompts for a password and shows the authenticator QR code:

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
- Container image versions are pinned in `Bootstrap/packages/images.py`; `--list-images` shows
  them. See [Configuration](../reference/configuration.md#container-image-pins).
- See [Configuration](../reference/configuration.md) for the `[UserData.Servers]`, WordPress, and Cockpit
  keys these commands read.
