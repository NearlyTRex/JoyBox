# Git Hooks

Version-controlled git hooks for this repo. Activated by pointing git at this directory:

```bash
git config core.hooksPath .githooks
```

`core.hooksPath` lives in `.git/config`, which is **not** cloned. The JoyBox bootstrap does
this for you via its `githooks` component:

```bash
python3 bootstrap.py -a setup -t local_ubuntu --components githooks
```

(run on a fresh clone, or as part of a full `setup`). The one-liner above is the manual
equivalent.

## pre-commit — secret scanner

Blocks a commit that:

- **stages a sensitive file** — `JoyBox.ini`, `.env*`, `.netrc`, `.npmrc`,
  `.audible_authcode`, SSH private keys (`id_rsa`/`id_ed25519`/…), `*.pem`/`*.key`/`*.p12`/
  `*.pfx`/`*.keystore`/`*.jks`/`*.ppk`, `*credentials`, `*service-account*.json`; or
- **adds a line that looks like a secret** — private-key blocks, AWS access keys, GitHub /
  Slack tokens, Google API keys, credentials embedded in URLs, or an assignment to a
  `password`/`passphrase`/`secret`/`token`/`api_key`/`access_key`/`activation_bytes` field.

It needs only `python3`. If [`gitleaks`](https://github.com/gitleaks/gitleaks) is on `PATH`
it is also run (`gitleaks protect --staged`) as a second layer.

### False positives / bypass

- Mark a specific line as intentional: append `# pragma: allowlist secret` (or
  `gitleaks:allow`) to it.
- Skip the hook for one commit (use deliberately): `git commit --no-verify`.

This is defense-in-depth alongside `.gitignore`, not a replacement for keeping real secrets
(like `JoyBox.ini`) out of the working tree.
