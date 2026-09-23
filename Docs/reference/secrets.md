# Secrets

[← Docs index](../README.md)

`~/JoyBox.ini` holds passphrases, API keys and tokens. A file like that is read by accident more
often than it is read on purpose — a log line, a screenshot, a backup of the home directory, a
command run while looking at something else, an editor session shared over a call.

Any field can hold a **reference** instead of the secret. The file then names where the secret
lives, and the secret is fetched from 1Password at the moment that field is actually used.

```ini
[UserData.Protection]
general_passphrase = op://Private/JoyBox/general_passphrase
locker_passphrase  = op://Private/JoyBox/locker_passphrase

[UserData.Share]
locker_hetzner_token = op://Private/JoyBox/hetzner_token
```

Anything that does not start with `op://` is used exactly as written, so this can be adopted one
field at a time.

## What this does and does not protect against

**It protects against a secret being read by accident.** There is nothing in the file worth
stealing, so the copy in your backups, the one in a screenshot and the one an editor left in a
swap file are all worthless.

**It does not protect against a program running as you reading one on purpose.** Anything that
can run `op` can resolve a reference — that is the same authority it would have had over a plain
file, and no file format, encrypted mount or permission bit changes it. What changes is that
reading a secret becomes a deliberate act rather than a side effect of reading a config file.

The unlock prompt is where that distinction is worth something: with the desktop app integration
below, a read your vault is not already unlocked for puts a prompt on your screen, which you can
refuse.

## Setting it up

Install the tool — the JoyBox 1Password installer now does both halves:

```bash
sudo apt install 1password-cli
```

Then turn on the desktop integration in **1Password → Settings → Developer → Integrate with
1Password CLI**. The tool asks the app to unlock; nothing is stored in a file.

A **service account token** in `.bashrc` is the other way to authenticate, and it is worse for a
workstation: the token is itself a secret sitting in a file, it opens every vault it is scoped
to, and it never prompts. It belongs on a headless machine that has to run unattended, scoped to
a single vault, and nowhere else.

## Where to keep them

One item holding a concealed field per setting, rather than an item per secret. A **Secure Note**
suits it better than a Password item, which has a password field you would leave unused.

```
Vault:  Private
Item:   JoyBox
Fields: general_passphrase, locker_passphrase, locker_hetzner_token, ...
```

Give each field the **Password** type rather than Text. A text field resolves the same, but it is
shown in the clear in the app and by `op item get`, which defeats the point as soon as you open
the item to check a label. Name the fields after the ini keys and avoid spaces.

A field inside a **named section** carries the section in its reference:

```
op://Private/JoyBox/Lockers/hetzner_token
```

Fields outside one skip that segment. Grouping is worth it for a long note, but renaming a
section breaks every reference beneath it. The app's right-click → **Copy Secret Reference** gives
the exact string, including any section — worth using once to confirm the shape.

Add fields for secrets you already have in the app rather than with `op item edit`, which puts
the value in shell history and in a command line readable from `/proc`. For a secret being made
fresh, the tool is better, since the value is never typed:

```bash
op item create --category="Secure Note" --title=JoyBox --vault=Private \
  --generate-password=letters,digits,symbols,32
```

Check a reference resolves before putting it in the file:

```bash
op read 'op://Private/JoyBox/locker_passphrase' | wc -c
```

A byte count says it resolved and that the length looks right, without putting the secret on the
screen or in the scrollback.

## Fields worth converting

| Section | Fields |
|---------|--------|
| `UserData.Protection` | `general_passphrase`, `locker_passphrase` |
| `UserData.Share` | `locker_*_passphrase`, `locker_*_token` |
| `UserData.Wordpress` | `wordpress_db_pass`, `wordpress_db_root_pass`, `wordpress_admin_pass` |
| `UserData.FileBrowser` | `filebrowser_admin_pass` |
| `UserData.Autoinstall` | `autoinstall_password_hash` |
| `Tools.*` | `github_access_token`, `steam_web_api_key`, `steamgriddb_api_key`, `anthropic_api_key`, `google_search_engine_api_key`, `humblebundle_auth_token` |

## How it behaves

A secret is fetched the first time its field is read and kept in memory for that run only, so a
field read in a loop prompts once rather than every time. Fields that are never read are never
fetched, so one command does not unlock the whole file.

A reference that cannot be resolved — tool missing, vault locked, item renamed — reads as
**nothing**, with an error naming the reference. It deliberately does not fall back to the
reference string: a passphrase of `op://...` would encrypt an archive to a value nobody knows
they are using.

Writing settings back out keeps the reference. The secret never returns to the file.

A resolved secret does not reach the logs. Command logging already masks the values after
`--passphrase`, `--password`, `--token` and `--secret`.
