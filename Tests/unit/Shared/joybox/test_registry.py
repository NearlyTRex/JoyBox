# Imports
import pytest

# Local imports
from joybox import registry


###########################################################
# Registry files
#
# Wine prefix registry backups are exported, pruned and replayed on restore, so
# an entry dropped or mangled here is a lost game setting.
###########################################################

HEADER = "Windows Registry Editor Version 5.00"


def write_reg(path, text):
    with open(str(path), "w", encoding = "utf-16") as handle:
        handle.write(text)
    return str(path)


def sample(*entries):
    text = HEADER + "\n\n"
    for key, values in entries:
        text += "[%s]\n" % key
        if values:
            text += values + "\n"
        text += "\n"
    return text


ACME = ("HKEY_CURRENT_USER\\Software\\Acme", '"Install"="C:\\\\Games\\\\Acme"')
WINE = ("HKEY_CURRENT_USER\\Software\\Wine", '"Version"="win7"')
MICROSOFT = ("HKEY_CURRENT_USER\\Software\\Microsoft", '"Theme"="dark"')


def keys_of(data):
    return [entry["key"] for entry in data["entries"]]


###########################################################
# Reading
###########################################################

def test_a_registry_file_is_parsed(tmp_path):
    source = write_reg(tmp_path / "user.reg", sample(ACME))
    data = registry.read_registry_file(source)

    assert data["header"] == HEADER
    assert keys_of(data) == ["HKEY_CURRENT_USER\\Software\\Acme"]
    assert data["entries"][0]["value"] == '"Install"="C:\\\\Games\\\\Acme"'


def test_every_entry_is_parsed(tmp_path):
    source = write_reg(tmp_path / "user.reg", sample(ACME, WINE, MICROSOFT))
    data = registry.read_registry_file(source)

    assert len(data["entries"]) == 3


def test_a_multi_line_value_is_kept_whole(tmp_path):
    entry = ("HKEY_CURRENT_USER\\Software\\Acme", '"A"="1"\n"B"="2"\n"C"="3"')
    source = write_reg(tmp_path / "user.reg", sample(entry))
    data = registry.read_registry_file(source)

    assert data["entries"][0]["value"] == '"A"="1"\n"B"="2"\n"C"="3"'


def test_a_key_with_no_values_is_kept(tmp_path):
    # An empty key still has to exist in the prefix for some installers.
    source = write_reg(tmp_path / "user.reg", sample(("HKEY_CURRENT_USER\\Software\\Acme", "")))
    data = registry.read_registry_file(source)

    assert keys_of(data) == ["HKEY_CURRENT_USER\\Software\\Acme"]
    assert data["entries"][0]["value"] == ""


def test_a_missing_registry_file_reads_as_empty(tmp_path):
    assert registry.read_registry_file(str(tmp_path / "absent.reg")) == {}


def test_a_utf8_registry_file_reads_as_empty(tmp_path):
    # Windows writes .reg as UTF-16; a mis-encoded file must not parse into
    # half-decoded garbage entries.
    target = tmp_path / "user.reg"
    target.write_text(sample(ACME), encoding = "utf8")

    assert registry.read_registry_file(str(target)) == {}


def test_a_file_with_only_a_header_has_no_entries(tmp_path):
    source = write_reg(tmp_path / "user.reg", HEADER + "\n\n")
    data = registry.read_registry_file(source)

    assert data["header"] == HEADER
    assert data["entries"] == []


def test_an_empty_file_parses_to_an_empty_registry(tmp_path):
    source = write_reg(tmp_path / "user.reg", "")
    data = registry.read_registry_file(source)

    assert data == {"header": "", "entries": []}


def test_pretending_does_not_read_a_registry_file(tmp_path):
    source = write_reg(tmp_path / "user.reg", sample(ACME))
    data = registry.read_registry_file(source, pretend_run = True)

    assert data["entries"] == []


def test_a_unicode_value_survives_reading(tmp_path):
    entry = ("HKEY_CURRENT_USER\\Software\\Acme", '"Title"="\u30c9\u30e9\u30b4\u30f3"')
    source = write_reg(tmp_path / "user.reg", sample(entry))
    data = registry.read_registry_file(source)

    assert "\u30c9\u30e9\u30b4\u30f3" in data["entries"][0]["value"]


###########################################################
# Filtering
###########################################################

def test_an_ignored_key_is_dropped(tmp_path):
    source = write_reg(tmp_path / "user.reg", sample(ACME, WINE))
    data = registry.read_registry_file(
        source, ignore_keys = ["HKEY_CURRENT_USER\\Software\\Wine"])

    assert keys_of(data) == ["HKEY_CURRENT_USER\\Software\\Acme"]


def test_ignoring_matches_by_prefix(tmp_path):
    # The config lists parent keys; every subkey below them goes too.
    child = ("HKEY_CURRENT_USER\\Software\\Wine\\Drives", '"c:"="../drive_c"')
    source = write_reg(tmp_path / "user.reg", sample(ACME, child))
    data = registry.read_registry_file(
        source, ignore_keys = ["HKEY_CURRENT_USER\\Software\\Wine"])

    assert keys_of(data) == ["HKEY_CURRENT_USER\\Software\\Acme"]


def test_several_ignored_keys_are_all_dropped(tmp_path):
    source = write_reg(tmp_path / "user.reg", sample(ACME, WINE, MICROSOFT))
    data = registry.read_registry_file(source, ignore_keys = [
        "HKEY_CURRENT_USER\\Software\\Wine",
        "HKEY_CURRENT_USER\\Software\\Microsoft",
    ])

    assert keys_of(data) == ["HKEY_CURRENT_USER\\Software\\Acme"]


def test_only_kept_keys_survive(tmp_path):
    source = write_reg(tmp_path / "user.reg", sample(ACME, WINE, MICROSOFT))
    data = registry.read_registry_file(
        source, keep_keys = ["HKEY_CURRENT_USER\\Software\\Acme"])

    assert keys_of(data) == ["HKEY_CURRENT_USER\\Software\\Acme"]


def test_keeping_matches_by_prefix(tmp_path):
    child = ("HKEY_CURRENT_USER\\Software\\Acme\\Settings", '"Sound"="1"')
    source = write_reg(tmp_path / "user.reg", sample(ACME, child, WINE))
    data = registry.read_registry_file(
        source, keep_keys = ["HKEY_CURRENT_USER\\Software\\Acme"])

    assert len(data["entries"]) == 2


def test_an_empty_keep_list_keeps_everything(tmp_path):
    # A game that registers nothing must not silently drop the whole backup.
    source = write_reg(tmp_path / "user.reg", sample(ACME, WINE))
    data = registry.read_registry_file(source, keep_keys = [])

    assert len(data["entries"]) == 2


def test_ignoring_wins_over_keeping(tmp_path):
    source = write_reg(tmp_path / "user.reg", sample(ACME))
    data = registry.read_registry_file(
        source,
        ignore_keys = ["HKEY_CURRENT_USER\\Software\\Acme"],
        keep_keys = ["HKEY_CURRENT_USER\\Software\\Acme"])

    assert data["entries"] == []


def test_a_key_matching_nothing_kept_is_dropped(tmp_path):
    source = write_reg(tmp_path / "user.reg", sample(ACME))
    data = registry.read_registry_file(
        source, keep_keys = ["HKEY_CURRENT_USER\\Software\\Other"])

    assert data["entries"] == []


###########################################################
# Writing
###########################################################

def test_a_registry_file_is_written(tmp_path):
    data = {"header": HEADER, "entries": [
        {"key": "HKEY_CURRENT_USER\\Software\\Acme", "value": '"Install"="C:"'},
    ]}
    target = tmp_path / "out.reg"

    assert registry.write_registry_file(str(target), data) is True
    text = target.read_text(encoding = "utf-16")
    assert text.startswith(HEADER)
    assert "[HKEY_CURRENT_USER\\Software\\Acme]" in text


def test_a_written_registry_file_is_utf16(tmp_path):
    # Wine and regedit both reject a UTF-8 .reg.
    data = {"header": HEADER, "entries": []}
    target = tmp_path / "out.reg"
    registry.write_registry_file(str(target), data)

    assert target.read_bytes()[:2] in (b"\xff\xfe", b"\xfe\xff")


def test_writing_to_an_unwritable_path_reports_failure(tmp_path):
    data = {"header": HEADER, "entries": []}

    assert registry.write_registry_file(str(tmp_path / "missing" / "out.reg"), data) is False


def test_pretending_does_not_write_a_registry_file(tmp_path):
    data = {"header": HEADER, "entries": []}
    target = tmp_path / "out.reg"

    assert registry.write_registry_file(str(target), data, pretend_run = True) is True
    assert not target.exists()


###########################################################
# Round trip
###########################################################

def test_a_registry_file_round_trips(tmp_path):
    source = write_reg(tmp_path / "user.reg", sample(ACME, WINE, MICROSOFT))
    original = registry.read_registry_file(source)

    target = str(tmp_path / "out.reg")
    registry.write_registry_file(target, original)

    assert registry.read_registry_file(target) == original


def test_a_pruned_registry_round_trips(tmp_path):
    source = write_reg(tmp_path / "user.reg", sample(ACME, WINE))
    original = registry.read_registry_file(
        source, ignore_keys = ["HKEY_CURRENT_USER\\Software\\Wine"])

    target = str(tmp_path / "out.reg")
    registry.write_registry_file(target, original)
    restored = registry.read_registry_file(target)

    assert keys_of(restored) == ["HKEY_CURRENT_USER\\Software\\Acme"]


def test_a_multi_line_value_round_trips(tmp_path):
    entry = ("HKEY_CURRENT_USER\\Software\\Acme", '"A"="1"\n"B"="2"')
    source = write_reg(tmp_path / "user.reg", sample(entry))
    original = registry.read_registry_file(source)

    target = str(tmp_path / "out.reg")
    registry.write_registry_file(target, original)

    assert registry.read_registry_file(target) == original


def test_a_unicode_value_round_trips(tmp_path):
    entry = ("HKEY_CURRENT_USER\\Software\\Acme", '"Title"="\u30c9\u30e9\u30b4\u30f3"')
    source = write_reg(tmp_path / "user.reg", sample(entry))
    original = registry.read_registry_file(source)

    target = str(tmp_path / "out.reg")
    registry.write_registry_file(target, original)

    assert registry.read_registry_file(target) == original


###########################################################
# Backing up
#
# Each export key is written to its own temporary file; exporting them all to
# one path leaves only the last key, losing everything the others held.
###########################################################

@pytest.fixture
def fake_exports(monkeypatch):
    exported = {}

    def export(registry_file, registry_key, options, **kwargs):
        entries = exported.get(registry_key)
        if entries is None:
            return False
        write_reg(registry_file, sample(*entries))
        return True

    monkeypatch.setattr(registry, "export_registry_file", export)
    return exported


def test_every_export_key_reaches_the_backup(tmp_path, fake_exports):
    fake_exports["HKCU\\Software"] = [ACME]
    fake_exports["HKLM\\Software"] = [("HKEY_LOCAL_MACHINE\\Software\\Acme", '"Shared"="1"')]
    target = str(tmp_path / "setup.reg")

    assert registry.backup_user_registry(
        registry_file = target,
        options = None,
        export_keys = ["HKCU\\Software", "HKLM\\Software"]) is True

    assert keys_of(registry.read_registry_file(target)) == [
        "HKEY_CURRENT_USER\\Software\\Acme",
        "HKEY_LOCAL_MACHINE\\Software\\Acme",
    ]


def test_the_backup_keeps_a_single_header(tmp_path, fake_exports):
    fake_exports["HKCU\\Software"] = [ACME]
    fake_exports["HKLM\\Software"] = [("HKEY_LOCAL_MACHINE\\Software\\Acme", '"Shared"="1"')]
    target = str(tmp_path / "setup.reg")
    registry.backup_user_registry(
        registry_file = target,
        options = None,
        export_keys = ["HKCU\\Software", "HKLM\\Software"])

    text = open(target, encoding = "utf-16").read()
    assert text.count(HEADER) == 1
    assert text.startswith(HEADER)


def test_a_single_export_key_is_backed_up(tmp_path, fake_exports):
    fake_exports["HKCU\\Software"] = [ACME]
    target = str(tmp_path / "game.reg")
    registry.backup_user_registry(
        registry_file = target, options = None, export_keys = ["HKCU\\Software"])

    assert keys_of(registry.read_registry_file(target)) == ["HKEY_CURRENT_USER\\Software\\Acme"]


def test_filters_apply_across_every_export_key(tmp_path, fake_exports):
    fake_exports["HKCU\\Software"] = [ACME, WINE]
    fake_exports["HKLM\\Software"] = [
        ("HKEY_LOCAL_MACHINE\\Software\\Acme", '"Shared"="1"'),
        ("HKEY_LOCAL_MACHINE\\Software\\Microsoft", '"Theme"="dark"'),
    ]
    target = str(tmp_path / "setup.reg")
    registry.backup_user_registry(
        registry_file = target,
        options = None,
        export_keys = ["HKCU\\Software", "HKLM\\Software"],
        ignore_keys = [
            "HKEY_CURRENT_USER\\Software\\Wine",
            "HKEY_LOCAL_MACHINE\\Software\\Microsoft",
        ])

    assert keys_of(registry.read_registry_file(target)) == [
        "HKEY_CURRENT_USER\\Software\\Acme",
        "HKEY_LOCAL_MACHINE\\Software\\Acme",
    ]


def test_a_failed_export_abandons_the_backup(tmp_path, fake_exports):
    # A partial backup restored later would look complete and be wrong.
    fake_exports["HKCU\\Software"] = [ACME]
    target = tmp_path / "setup.reg"

    assert registry.backup_user_registry(
        registry_file = str(target),
        options = None,
        export_keys = ["HKCU\\Software", "HKLM\\Software"]) is False
    assert not target.exists()


def test_no_export_keys_writes_an_empty_backup(tmp_path, fake_exports):
    target = str(tmp_path / "setup.reg")

    assert registry.backup_user_registry(
        registry_file = target, options = None, export_keys = []) is True
    assert registry.read_registry_file(target)["entries"] == []


def test_backing_up_removes_its_export_files(tmp_path, fake_exports, monkeypatch):
    fake_exports["HKCU\\Software"] = [ACME]
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    monkeypatch.setattr(registry.fileops, "create_temporary_directory", lambda **kwargs: (True, str(work_dir)))

    registry.backup_user_registry(
        registry_file = str(tmp_path / "setup.reg"), options = None, export_keys = ["HKCU\\Software"])
    assert not work_dir.exists()


def test_no_temporary_directory_abandons_the_backup(tmp_path, monkeypatch):
    monkeypatch.setattr(registry.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))
    target = tmp_path / "setup.reg"

    assert registry.backup_user_registry(registry_file = str(target), options = None) is False
    assert not target.exists()


###########################################################
# Failure handling
###########################################################

def test_an_unreadable_registry_file_quits_when_asked(tmp_path):
    with pytest.raises(SystemExit):
        registry.read_registry_file(str(tmp_path / "missing.reg"), verbose = True, exit_on_failure = True)


def test_an_unwritable_registry_file_quits_when_asked(tmp_path):
    data = {"header": HEADER, "entries": []}
    with pytest.raises(SystemExit):
        registry.write_registry_file(
            str(tmp_path / "missing" / "user.reg"), data, verbose = True, exit_on_failure = True)


def test_a_key_with_no_values_is_written_bare(tmp_path):
    target = str(tmp_path / "user.reg")
    data = {"header": HEADER, "entries": [{"key": "HKEY_CURRENT_USER\\Empty", "value": ""}]}

    assert registry.write_registry_file(target, data)
    with open(target, encoding = "utf-16") as handle:
        assert handle.read() == HEADER + "\n\n[HKEY_CURRENT_USER\\Empty]\n\n"


###########################################################
# Exporting and importing through reg
###########################################################

@pytest.fixture
def reg_runs(monkeypatch):
    runs = {"calls": [], "code": 0, "creates": True}

    def run_returncode_command(cmd, options, **kwargs):
        runs["calls"].append((cmd, options))
        if runs["creates"] and cmd[1] == "export":
            write_reg(cmd[3], sample(ACME))
        return runs["code"]
    monkeypatch.setattr(registry.command, "run_returncode_command", run_returncode_command)
    return runs


def test_exporting_runs_reg_export_in_the_prefix(tmp_path, reg_runs):
    target = str(tmp_path / "out.reg")
    options = registry.command.create_command_options()

    assert registry.export_registry_file(target, "HKCU\\Software", options)
    cmd, used = reg_runs["calls"][0]
    assert cmd == ["reg", "export", "\"HKCU\\Software\"", target, "/y"]
    assert used.force_prefix() and used.is_shell()
    assert used.get_blocking_processes() == ["reg"]
    assert not options.force_prefix()


def test_a_failed_export_reports_failure(tmp_path, reg_runs):
    reg_runs["code"] = 1
    options = registry.command.create_command_options()
    assert registry.export_registry_file(str(tmp_path / "out.reg"), "HKCU\\Software", options) is False


def test_an_export_that_writes_nothing_reports_failure(tmp_path, reg_runs):
    reg_runs["creates"] = False
    options = registry.command.create_command_options()
    assert registry.export_registry_file(str(tmp_path / "out.reg"), "HKCU\\Software", options) is False


def test_importing_runs_reg_import_in_the_prefix(tmp_path, reg_runs):
    source = write_reg(tmp_path / "in.reg", sample(ACME))
    options = registry.command.create_command_options()

    assert registry.import_registry_file(source, options)
    cmd, used = reg_runs["calls"][0]
    assert cmd == ["reg", "import", source]
    assert used.force_prefix()
    assert used.get_blocking_processes() == ["reg"]


def test_a_failed_import_reports_failure(tmp_path, reg_runs):
    reg_runs["code"] = 1
    source = write_reg(tmp_path / "in.reg", sample(ACME))
    assert registry.import_registry_file(source, registry.command.create_command_options()) is False
