# Tests

Mirrors the repo layout: `unit/` and `integration/`, each containing `Bootstrap`,
`Scripts` and `Shared`.

## Running

```bash
# Everything, from the repo root
pytest Tests

# One area
pytest Tests/unit/Shared
pytest Tests/unit/Bootstrap/packages/test_aptget.py

# Skip the slow subprocess and docker tests
pytest Tests -m "not slow"

# Only what needs docker
pytest Tests -m requires_docker
```

The config lives in `Tests/pytest.ini`, so pytest needs the path — a bare
`pytest` from the repo root will not pick it up. `cd Tests && pytest` also works.

## Layout

Test files mirror the path of the source they cover:

```
Shared/joybox/cmdline.py            → Tests/unit/Shared/joybox/test_cmdline.py
Bootstrap/packages/aptget.py        → Tests/unit/Bootstrap/packages/test_aptget.py
Bootstrap/installers/installer_certbot.py
                                    → Tests/unit/Bootstrap/installers/test_installer_certbot.py
Shared/joybox/connection/connection_local.py
                                    → Tests/integration/Shared/joybox/connection/test_connection_local.py
```

An invariant that spans a whole directory rather than one module goes in a file
named after the package — `Tests/unit/Bootstrap/installers/test_installers.py`
holds the checks that run across every installer.

| Directory | What belongs there |
|---|---|
| `unit/Shared` | The bulk of the value. `Shared/joybox` holds the logic, and most of it is pure functions with real contracts |
| `unit/Bootstrap` | Installer behaviour via the fake connection, plus package-list and template invariants |
| `unit/Scripts` | Only the conventions that keep `Scripts/bin` thin — not the wrappers themselves |
| `integration/Bootstrap` | Generated compose files, vhosts and shell scripts handed to docker and bash for judgement |
| `integration/Shared` | `ConnectionLocal` against a real filesystem |
| `integration/Scripts` | Every CLI launched as a subprocess with `--help` |

Because the tree mirrors the source, `unit/` and `integration/` contain files
with the same basename. `pytest.ini` sets `--import-mode=importlib` for that
reason — the default mode derives module names from the basename alone and
collides.

## How the fixtures work

`conftest.py` puts `Shared/`, `Bootstrap/` and `Tests/` on `sys.path`, because
both trees are consumed off disk rather than installed — the same thing
`bootstrap.py` and every `Scripts/bin/*.py` does.

**`isolated_settings`** — `joybox.settings` is process-global (a parser plus an
in-memory overlay that `set_value` writes to). Any test that touches settings
must use this fixture, or its values leak into whatever runs next in whatever
order pytest picked.

**`recording_connection`** — a `RecordingConnection` from `fakes.py`. Installers
never shell out directly; every side effect goes through `self.connection`, an
abstract ~30-method interface. That makes it the one seam worth faking: an
installer can be driven end to end and then asserted on, with nothing installed.

```python
def test_selfsigned_never_contacts_lets_encrypt(isolated_settings, recording_connection):
    isolated_settings.set_value("UserData.Servers", "tls_mode", "selfsigned")
    certbot = installers.Certbot(recording_connection)
    certbot.install()

    assert not recording_connection.ran("register")
    assert recording_connection.ran("openssl", "req", "-x509")
```

Helpers on the double: `ran(*fragments)` (one command containing all fragments),
`command_strings()`, `called(method)`, `written(path_fragment)`, plus recorded
lists such as `permissions`, `moved`, `crontab_added`.

**One thing to know about the double.** `Installer.__init__` does
`self.connection = connection.copy()`, and the base `copy()` is a deepcopy — so
an installer would otherwise record into a clone the test cannot see.
`RecordingConnection.copy()` returns `self` for exactly this reason. Any future
double needs to do the same.

## Conventions

- Test names state the behaviour, not the function: `test_selfsigned_never_contacts_lets_encrypt`,
  not `test_install_2`.
- Comments are short and factual — one line, stating an invariant or a
  consequence. No narration of when or how something was changed; git history
  covers that.
- Mark anything involving a subprocess or container `@pytest.mark.slow`, and
  anything needing a binary with `requires_docker` / `requires_nginx` plus a
  `skipif`, so the suite still runs on a machine without them.
- **Tests assert the intended contract.** If a test fails because the source is
  wrong, fix the source. Do not add an `xfail` or rewrite the assertion to match
  broken behaviour.

## Known gaps

- The shell under `Bootstrap/scripts/` has no tests. `common.sh` is the largest
  single file in the tree and carries the firewall, sshd and verification logic.
  Deferred deliberately — that logic is moving to Python.
- `Shared/joybox` is 58k lines across 242 files. The pure modules are covered;
  `collection/`, `config/`, `stores/`, `emulators/` and `tools/` are not.
- The audio and ollama logic moved out of `Scripts/bin` has dispatch and parsing
  tests, but nothing exercises the parts that touch real media files or a
  running Ollama.
- Nothing exercises a real remote deploy. `Bootstrap/scripts/verify_hardening.sh`
  covers that against the rehearsal VM — see
  [local testing](../Bootstrap/docs/local-testing.md).
