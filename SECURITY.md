# Security Policy

JoyBox is a personal project, maintained in spare time and shared as is. Security reports are
still welcome: it installs software, provisions servers and handles credentials, so a flaw in it
can matter even to one user.

## Supported versions

Fixes go to `main` and ship in the next release. Only the latest release and `main` are
supported; there are no backports.

| Version | Supported |
|---------|-----------|
| `main` | Yes |
| Latest [release](https://github.com/NearlyTRex/JoyBox/releases/latest) | Yes |
| Anything older | No |

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub instead:

**[Report a vulnerability](https://github.com/NearlyTRex/JoyBox/security/advisories/new)**
(the repository's **Security** tab → **Report a vulnerability**)

That opens a private advisory only you and the maintainer can see. Please include:

- what is affected: the file, command or bootstrap component, and the version or commit
- what an attacker could do, and what they would need first (network access, a local account,
  a crafted file, a malicious server)
- steps to reproduce it, or a proof of concept

Don't put real secrets in a report, yours or anyone else's. A redacted value or a made-up one
shows the problem just as well.

Reports are answered on a best-effort basis. Once a fix is ready, the advisory is published with
credit to the reporter, unless you'd rather not be named.

## Scope

**In scope:** everything in this repository, including:

- the `joybox` package and its commands (`Shared/joybox/`)
- the installer (`install.sh`), the bootstrap and its components (`bootstrap.py`, `Bootstrap/`)
- how secrets are handled: `op://` references, the keys the bootstrap writes, and what reaches
  logs, files and command lines (see [Secrets](Docs/reference/secrets.md))
- the hardening a provisioned server receives (see
  [Hardening](Docs/remote-server/hardening.md)), and the services the bootstrap deploys onto it
- the git hooks (`.githooks/`) and the CI workflows (`.github/`)

**Out of scope:**

- flaws in the third-party programs JoyBox installs (report those to their own projects)
- attacks that need code already running as the user (see
  [what secrets references protect against](Docs/reference/secrets.md#what-this-does-and-does-not-protect-against))
- machines or servers whose JoyBox-managed configuration was changed by hand
