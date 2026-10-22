# Tests

Mirrors the repo layout: `unit/` and `integration/`, each containing `Bootstrap`,
`Scripts` and `Shared`.

## Running

The meta suite, the hermetic seal, `requires_binary`, and the `shell_sandbox` and
shell coverage plugins come from [pytest-testrex](https://github.com/NearlyTRex/TestRex),
which `requirements-dev.txt` installs and pytest loads by itself.

```bash
# Everything, from the repo root
pytest --rootdir=. Tests

# One area
pytest --rootdir=. Tests/unit/Shared
pytest --rootdir=. Tests/unit/Shared/joybox/bootstrap/packages/test_aptget.py

# Skip the slow subprocess and docker tests
pytest --rootdir=. Tests -m "not slow"

# Across every core, the way CI runs the unit tests
pytest --rootdir=. Tests/unit -n auto --dist loadfile
```

The config lives in `Tests/pytest.ini`, which pytest finds from the test paths,
but the rootdir has to be the repo root: the shell plugins resolve scripts from
it. The suite stops with the fix when it is not.

## Coverage

`coverage_tool run` measures the unit tests the way CI does and reports the
overall figure against CI's floor, each area of the library, the files missing
the most, and the functions no test runs. `coverage_tool report -m <module>`
details one module; see [its page](../Docs/reference/man/coverage_tool.md).

The shell under `Bootstrap/` and `install.sh` is measured separately, since
coverage.py never sees it, by pytest-testrex's shell coverage plugin. CI holds
it at 100%, counting the right-hand side of every `&&` and `||` as a statement of
its own, so an error handler needs a test where its command fails. To run it
locally:

```bash
pytest -c Tests/pytest.ini --rootdir=. Tests/unit \
    --shell-cov-source Bootstrap --shell-cov-source install.sh --shell-cov-branch --shell-cov-report
```

Every bash a test starts is traced through `BASH_ENV`, inherited from the
environment or, for a test that builds its own, from the `shell_traced_env`
fixture. A statement counts as run when any of its lines was, because bash
reports a multi-line command under its first or its last line depending on the
construct.

## Layout

Test files mirror the path of the source they cover:

```text
Shared/joybox/cmdline.py            → Tests/unit/Shared/joybox/test_cmdline.py
Shared/joybox/bootstrap/packages/aptget.py
                                    → Tests/unit/Shared/joybox/bootstrap/packages/test_aptget.py
Shared/joybox/bootstrap/installers/installer_certbot.py
                                    → Tests/unit/Shared/joybox/bootstrap/installers/test_installer_certbot.py
Bootstrap/scripts/common.sh         → Tests/unit/Bootstrap/scripts/test_hardening_contract.py
Shared/joybox/connection/connection_local.py
                                    → Tests/integration/Shared/joybox/connection/test_connection_local.py
```

An invariant that spans a whole directory rather than one module goes in a file
named after the package — `Tests/unit/Shared/joybox/bootstrap/installers/test_installers.py`
holds the checks that run across every installer.

| Directory | What belongs there |
|---|---|
| `unit/Shared` | The bulk of the value. `Shared/joybox` holds the logic, and most of it is pure functions with real contracts |
| `unit/Bootstrap` | Installer behaviour via the fake connection, plus package-list and template invariants |
| `integration/Bootstrap` | Generated compose files, vhosts and shell scripts handed to docker and bash for judgement |
| `integration/Shared` | `ConnectionLocal` running real commands, every command launched as a subprocess with `--help`, and wrappers run against the real tools they drive |

What decides the directory is whether a test needs a program outside this
process, not whether it touches real files: a test that works in `tmp_path`
with joybox and its Python dependencies alone is a unit test. CI runs only
`unit/`, so a test filed under `integration/` never counts toward coverage.

Because the tree mirrors the source, `unit/` and `integration/` contain files
with the same basename. `pytest.ini` sets `--import-mode=importlib` for that
reason — the default mode derives module names from the basename alone and
collides.

## How the fixtures work

The suite imports joybox from its install, the way the commands run, so run it
from a venv with this checkout installed (`pip install -e ".[dev]"`; the `python`
bootstrap component does this). `conftest.py` stops the run if joybox is missing
or is some other copy, and puts only `Tests/` on `sys.path`, for the helpers the
tests import by name. `unit/Shared/joybox/cli` checks the conventions that keep
the command modules thin, plus in-process tests of commands whose own logic
(selection, exit status) is worth pinning.

**`no_sealed_programs`** (autouse) — refuses real runs of `sudo`, `op`, `ssh`,
`virsh`, `systemctl` and the other programs in `SEALED_PROGRAMS`, whether through
`subprocess`, `os.system` or `os.exec*`. Together with the session `HOME`, the
generated settings file and `no_outbound_network`, it keeps every test off the
developer's machine, vault and servers. Replace the connection or command runner
with a fake instead.

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
    isolated_settings.set_value("UserData.Servers", "server_0_tls_mode", "selfsigned")
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

**`shell_sandbox`** — runs a script from `Bootstrap/` the way a fresh server
would: as root, inside an unprivileged user namespace with no network, where
`/etc`, `/var`, `/home`, `/root`, `/usr/local`, `/opt`, `/mnt`, `/srv` and `/tmp`
are empty directories the test owns. `PATH` holds recording stubs for anything
that changes a machine (`systemctl`, `apt-get`, `ufw`, `netplan`, `chown`, ...)
and an allowlist of harmless real tools, so an unplanned command fails rather
than running for real. Arrange with `write`, `add_user` and `stub(name, stdout,
code, script)`; read back with `read`, `exists`, `host_path`, `calls(name)` and
`ran(name, *args)`.

```python
def test_install_moves_boot_waiting_to_network_manager(server):
    server.run("Bootstrap/managers/manager_cockpit.sh", "install")

    assert server.ran("systemctl", "enable", "NetworkManager-wait-online.service")
```

It needs unprivileged user namespaces; where they are unavailable the tests skip,
except in CI, which fails them. **`shell_traced_env`** builds an
environment for tests that run bash directly instead, such as `install.sh`'s.

**`cli_helpers.py`** — `CommandHarness` runs a `joybox.cli` command in process, recording its
logs and previews; `Recorder` fakes a call; `assert_entry_points` checks `run()` and `__main__`.

## Conventions

- Test names state the behaviour, not the function: `test_selfsigned_never_contacts_lets_encrypt`,
  not `test_install_2`.
- Comments are short and factual — one line, stating an invariant or a
  consequence. No narration of when or how something was changed; git history
  covers that.
- Mark anything involving a subprocess or container `@pytest.mark.slow`.
- **Declare the programs a test needs.** `pytest.mark.requires_binary("docker")`
  for a program on `PATH` (`"a|b"` accepts either) and
  `pytest.mark.requires_tool("XorrISO")` for one from the JoyBox tool registry,
  at module (`pytestmark`), class or test level. Both are enforced while the
  tests are collected, so a machine without the program skips the test before
  any of its fixtures start. Don't check inside a test or fixture
  (`shutil.which` and `pytest.skip`, `skipif`). A test using `shell_sandbox`
  declares `"bash", "unshare"`, one using `shell_traced_env` `"bash"`, and
  every integration file declares at least one program, or runs this
  interpreter in a subprocess (`sys.executable`): one that needs neither
  belongs in `unit/`.
- **Tests assert the intended contract.** If a test fails because the source is
  wrong, fix the source. Do not add an `xfail` or rewrite the assertion to match
  broken behaviour.

## The meta suite

`unit/meta/test_testrex.py` runs [pytest-testrex](https://github.com/NearlyTRex/TestRex)'s
meta suite, configured in `pyproject.toml`'s `[tool.testrex]`. It holds every file under
`unit/` and `integration/` to the conventions above, statically, so a test that can't fail
is caught when it is written:

- **Quality:** a test that asserts nothing; checks that sit only inside an `if`, loop or
  `try` and may never run; `except ...: pass`; an assertion true by construction; a test
  whose only checks are `is not None` or `isinstance`; a helper pasted into several files
  (share it from the nearest `conftest.py` or a `*_helpers.py`).
- **Programs:** the `requires_binary` / `requires_tool` rules above, through any depth of
  fixtures. `requires_tool` is checked against the tool registry by the
  `pytest_testrex_requirement_checkers` hook in `conftest.py`.
- **Hygiene:** duplicate tests, helpers and constants, imports below the header, and the
  900 line limit.
- **Layout:** every directory mirrors one in the repository, and a split `test_<module>/`
  package covers a real module and holds only collectable tests.
- **Pylint:** `Tests/pylintrc` over every test file; any message fails.
- **Signatures:** an override in `joybox` keeps every parameter of the method it
  overrides, so a call through the base class works on every subclass.

There are no exemption lists to add to: when a rule trips, fix the test, or the
source when the test found a bug.

It also holds `Shared/` and `Scripts/` to the library standards: a comment above every
public definition that says more than its name, in at most three lines; file, JSON and
subprocess work through `fileops`, `serialization` and `command`; no printing or exiting
outside `cli/`; and no mutable defaults, narration, commented-out code, functions past 40
lines or three levels of nesting, or modules past 900 lines. The library had findings
under most of these when they were adopted, so `[tool.testrex.baseline]` records how many
each rule may have. A fix fails the suite until its baseline is lowered to match, so the
counts only fall; a new finding anywhere fails it at once.

## Known gaps

- The shell under `Bootstrap/` is fully covered in the sandbox, but against
  stubs: nothing checks that the real apt, systemd, nginx or certbot accept what
  it hands them. `verify_server` covers that on the rehearsal VM.
- `Shared/joybox` is 58k lines across 242 files. The pure modules are covered;
  `collection/`, `config/`, `stores/`, `emulators/` and `tools/` are not.
- The audio and ollama logic moved out of the command modules has dispatch and parsing
  tests, but nothing exercises the parts that touch real media files or a
  running Ollama.
- Nothing exercises a real remote deploy. `verify_server`
  covers that against the rehearsal VM — see
  [Testing the Remote Server](../Docs/testing/remote-server.md).

## Large test files

A test file that outgrows roughly 900 lines becomes a place where a second
definition of the same name goes unnoticed, and the second one silently wins.
When that happens, split the file into a directory of the same name:

```text
unit/Shared/joybox/test_sync.py
```

becomes

```text
unit/Shared/joybox/test_sync/
    conftest.py        fixtures shared by the files beside it
    sync_helpers.py    constants and plain helpers, imported by name
    test_naming.py
    test_flags.py
    test_transfers.py
    ...
```

One file per area of the module under test. Fixtures go in `conftest.py`,
where pytest finds them automatically. Constants and plain functions go in a
helpers module beside it, imported by name — `conftest.py` adds its own
directory to `sys.path` so that import resolves.

`unit/test_suite.py` enforces this: it fails on a file over the size limit, on
any name defined twice in one file, and on a repeated module level constant.
