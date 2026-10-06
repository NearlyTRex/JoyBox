# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import settings


###########################################################
# Settings
#
# Process-global: a configparser plus an in-memory overlay that set_value writes
# to. Every test points the module at a temp file and resets afterwards.
###########################################################

@pytest.fixture
def config_file(tmp_path):
    def write(contents):
        path = os.path.join(str(tmp_path), "JoyBox.ini")
        with open(path, "w") as config:
            config.write(contents)
        settings.reset()
        settings.set_settings_file(path)
        return path
    yield write
    settings.reset()


###########################################################
# Reading from the file
###########################################################

def test_a_value_is_read(config_file):
    config_file("[S]\nname = joybox\n")
    assert settings.get_value("S", "name") == "joybox"


def test_a_missing_field_returns_the_default(config_file):
    config_file("[S]\nname = joybox\n")
    assert settings.get_value("S", "absent", default_value = "fallback",
                              throw_exception = False) == "fallback"


def test_a_missing_section_returns_the_default(config_file):
    config_file("[S]\nname = joybox\n")
    assert settings.get_value("Absent", "name", default_value = "fallback",
                              throw_exception = False) == "fallback"


def test_a_missing_value_returns_none_rather_than_raising(config_file):
    # configparser's fallback covers a missing section as well as a missing
    # option, so absence never raises. DockerAppInstaller.validate_settings
    # depends on this to collect and report all missing keys at once.
    config_file("[S]\nname = joybox\n")

    assert settings.get_value("Absent", "name") is None
    assert settings.get_value("S", "absent") is None


def test_a_section_the_file_predates_falls_back_to_its_shipped_default(config_file):
    config_file("[S]\nname = joybox\n")

    assert settings.get_value("Tools.Tar", "tar_exe") == "tar"
    assert settings.get_integer_value("UserData.Cockpit", "cockpit_port_http") == 9090
    assert settings.get_bool_value("UserData.Share", "locker_hetzner_encrypted") is True


def test_a_field_the_file_predates_falls_back_to_its_shipped_default(config_file):
    config_file("[Tools.Tar]\ntar_install_dir = /opt/tar\n")

    assert settings.get_value("Tools.Tar", "tar_exe") == "tar"


def test_the_file_overrides_the_shipped_default(config_file):
    config_file("[Tools.Tar]\ntar_exe = gtar\n")

    assert settings.get_value("Tools.Tar", "tar_exe") == "gtar"


def test_the_callers_default_overrides_the_shipped_default(config_file):
    config_file("[S]\nname = joybox\n")

    assert settings.get_value("Tools.Tar", "tar_exe", default_value = "bsdtar") == "bsdtar"
    assert settings.get_integer_value("UserData.Cockpit", "cockpit_port_http", default_value = 1) == 1


def test_values_keep_their_interpolation_characters(config_file):
    # interpolation=None, so a password or path containing % survives verbatim.
    config_file("[S]\npassword = abc%def\n")
    assert settings.get_value("S", "password") == "abc%def"


###########################################################
# Typed reads
###########################################################

def test_integers_are_typed(config_file):
    config_file("[S]\nport = 8080\n")
    assert settings.get_integer_value("S", "port") == 8080


@pytest.mark.parametrize("written,expected", [
    ("True", True), ("true", True), ("yes", True), ("1", True),
    ("False", False), ("false", False), ("no", False), ("0", False),
])
def test_booleans_are_typed(config_file, written, expected):
    config_file(f"[S]\nflag = {written}\n")
    assert settings.get_bool_value("S", "flag") is expected


def test_a_list_is_split(config_file):
    config_file("[S]\nitems = a,b,c\n")
    assert settings.get_list_value("S", "items") == ["a", "b", "c"]


def test_a_path_expands_environment_variables(config_file, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/expanded")
    config_file("[S]\nroot = $JOYBOX_TEST_ROOT/data\n")
    assert settings.get_path_value("S", "root") == "/expanded/data"


###########################################################
# The overlay
###########################################################

def test_set_value_is_visible_immediately(config_file):
    config_file("[S]\nname = original\n")
    settings.set_value("S", "name", "overridden")

    assert settings.get_value("S", "name") == "overridden"


def test_set_value_does_not_touch_the_file(config_file):
    path = config_file("[S]\nname = original\n")
    settings.set_value("S", "name", "overridden")

    with open(path, "r") as config:
        assert "original" in config.read()


def test_set_value_works_for_a_section_the_file_lacks(config_file):
    config_file("[S]\nname = original\n")
    settings.set_value("Brand.New", "field", "value")

    assert settings.get_value("Brand.New", "field") == "value"


def test_overlay_integers_are_typed_like_file_integers(config_file):
    # The overlay must coerce the same way the file does.
    config_file("[S]\nport = 8080\n")
    settings.set_value("S", "port", "9090")

    assert settings.get_integer_value("S", "port") == 9090


def test_overlay_booleans_are_typed_like_file_booleans(config_file):
    # The string "False" is truthy, so an uncoerced overlay value misbranches.
    config_file("[S]\nflag = True\n")
    settings.set_value("S", "flag", "False")

    assert settings.get_bool_value("S", "flag") is False


def test_overlay_booleans_accept_a_real_bool(config_file):
    config_file("[S]\nflag = True\n")
    settings.set_value("S", "flag", False)

    assert settings.get_bool_value("S", "flag") is False


def test_an_uncoercible_overlay_value_honours_the_default(config_file):
    config_file("[S]\nport = 8080\n")
    settings.set_value("S", "port", "not-a-number")

    assert settings.get_integer_value("S", "port", default_value = 1,
                                      throw_exception = False) == 1


###########################################################
# Reset
###########################################################

def test_reset_clears_the_overlay(config_file):
    config_file("[S]\nname = original\n")
    settings.set_value("S", "name", "overridden")
    settings.reset()
    settings.set_settings_file(settings.get_settings_file())

    assert settings.get_value("S", "name") == "original"


###########################################################
# Saving
###########################################################

def test_save_persists_the_overlay(config_file):
    path = config_file("[S]\nname = original\n")
    settings.set_value("S", "name", "overridden")
    settings.save()

    with open(path, "r") as config:
        assert "overridden" in config.read()


def test_save_creates_a_missing_section(config_file):
    path = config_file("[S]\nname = original\n")
    settings.set_value("Brand.New", "field", "value")
    settings.save()

    with open(path, "r") as config:
        contents = config.read()
    assert "[Brand.New]" in contents
    assert "field = value" in contents


def test_a_saved_value_reads_back_after_a_reset(config_file):
    path = config_file("[S]\nport = 1\n")
    settings.set_value("S", "port", 8080)
    settings.save()

    settings.reset()
    settings.set_settings_file(path)

    assert settings.get_integer_value("S", "port") == 8080


def test_saving_a_bool_reads_back_as_a_bool(config_file):
    # save() stringifies, and configparser recognises "False" on the way back.
    path = config_file("[S]\nflag = True\n")
    settings.set_value("S", "flag", False)
    settings.save()

    settings.reset()
    settings.set_settings_file(path)

    assert settings.get_bool_value("S", "flag") is False


###########################################################
# File location
###########################################################

def test_the_settings_file_can_be_pointed_elsewhere(config_file):
    path = config_file("[S]\nname = first\n")
    assert settings.get_settings_file() == path


def test_switching_files_switches_the_values(tmp_path):
    # bootstrap.py -c relies on this for a fully independent config.
    first = os.path.join(str(tmp_path), "first.ini")
    second = os.path.join(str(tmp_path), "second.ini")
    with open(first, "w") as config:
        config.write("[S]\nname = first\n")
    with open(second, "w") as config:
        config.write("[S]\nname = second\n")

    settings.reset()
    settings.set_settings_file(first)
    assert settings.get_value("S", "name") == "first"

    settings.set_settings_file(second)
    assert settings.get_value("S", "name") == "second"

    settings.reset()


def test_is_present_reflects_the_file(tmp_path):
    settings.reset()
    settings.set_settings_file(os.path.join(str(tmp_path), "absent.ini"))
    assert settings.is_present() is False

    present = os.path.join(str(tmp_path), "present.ini")
    with open(present, "w") as config:
        config.write("[S]\n")
    settings.set_settings_file(present)
    assert settings.is_present() is True

    settings.reset()


###########################################################
# Introspection
###########################################################

def test_sections_are_listed(config_file):
    config_file("[A]\nx = 1\n\n[B]\ny = 2\n")
    assert sorted(settings.get_sections()) == ["A", "B"]


def test_section_and_field_presence(config_file):
    config_file("[A]\nx = 1\n")

    assert settings.has_section("A") is True
    assert settings.has_section("Z") is False
    assert settings.has_field("A", "x") is True
    assert settings.has_field("A", "z") is False


###########################################################
# Secrets kept out of the file
#
# A field may hold a reference instead of a secret, so that what is on disk
# gives up nothing when it is read by accident. The resolution happens here,
# at the one point every string setting passes through.
###########################################################

SECRET_REFERENCE = "op://Private/JoyBox/locker_passphrase"
SECRET_VALUE = "correct-horse-battery-staple"


@pytest.fixture
def vault(monkeypatch):
    from joybox import secretstore

    asked = []

    def resolve(reference, verbose = False):
        asked.append(reference)
        return SECRET_VALUE

    secretstore.clear_resolved_secrets()
    monkeypatch.setattr(secretstore, "resolve_secret_reference", resolve)
    yield asked
    secretstore.clear_resolved_secrets()


def test_a_reference_in_the_file_reads_as_the_secret(config_file, vault):
    config_file("[UserData.Protection]\nlocker_passphrase = %s\n" % SECRET_REFERENCE)

    assert settings.get_value("UserData.Protection", "locker_passphrase") == SECRET_VALUE


def test_an_ordinary_value_is_not_sent_to_the_vault(config_file, vault):
    config_file("[S]\nname = joybox\n")

    assert settings.get_value("S", "name") == "joybox"
    assert vault == []


def test_a_field_that_is_never_read_is_never_resolved(config_file, vault):
    # Unlocking prompts, so reading one field must not fetch every secret in
    # the file.
    config_file(
        "[S]\nfirst = %s\nsecond = op://Private/JoyBox/other\n" % SECRET_REFERENCE)

    settings.get_value("S", "first")

    assert vault == [SECRET_REFERENCE]


def test_a_reference_resolves_through_a_path_value(config_file, vault):
    config_file("[S]\nkey_file = %s\n" % SECRET_REFERENCE)

    assert settings.get_path_value("S", "key_file") == SECRET_VALUE


def test_a_reference_set_at_runtime_is_resolved(config_file, vault):
    config_file("[S]\n")
    settings.set_value("S", "locker_passphrase", SECRET_REFERENCE)

    assert settings.get_value("S", "locker_passphrase") == SECRET_VALUE


def test_saving_writes_the_reference_and_not_the_secret(config_file, vault):
    # The whole point is that the file holds nothing worth stealing; a save
    # that wrote back what was read would undo it on the first write.
    path = config_file("[UserData.Protection]\nlocker_passphrase = %s\n" % SECRET_REFERENCE)
    settings.get_value("UserData.Protection", "locker_passphrase")
    settings.set_value("S", "other", "plain")

    settings.save()

    with open(path) as written:
        contents = written.read()
    assert SECRET_REFERENCE in contents
    assert SECRET_VALUE not in contents


###########################################################
# Unreadable files and uncoercible values
###########################################################

MALFORMED = "no section header here\n"


def test_fields_are_listed_and_a_missing_section_has_none(config_file):
    config_file("[A]\nx = 1\ny = 2\n")

    assert settings.get_fields("A") == ["x", "y"]
    assert settings.get_fields("Z") == []


@pytest.mark.parametrize("call", [
    lambda: settings.get_sections(),
    lambda: settings.get_fields("A"),
    lambda: settings.has_section("A"),
    lambda: settings.has_field("A", "x"),
    lambda: settings.get_value("A", "x"),
    lambda: settings.get_integer_value("A", "x"),
    lambda: settings.get_bool_value("A", "x"),
    lambda: settings.get_path_value("A", "x"),
    lambda: settings.get_list_value("A", "x"),
])
def test_a_malformed_file_raises_a_runtime_error_naming_the_file(config_file, call):
    path = config_file(MALFORMED)

    with pytest.raises(RuntimeError, match = path):
        call()


@pytest.mark.parametrize("call, expected", [
    (lambda: settings.get_sections(throw_exception = False), []),
    (lambda: settings.get_fields("A", throw_exception = False), []),
    (lambda: settings.has_section("A", throw_exception = False), False),
    (lambda: settings.has_field("A", "x", throw_exception = False), False),
    (lambda: settings.get_value("A", "x", default_value = "d", throw_exception = False), "d"),
    (lambda: settings.get_integer_value("A", "x", default_value = 3, throw_exception = False), 3),
    (lambda: settings.get_bool_value("A", "x", default_value = True, throw_exception = False),
     True),
])
def test_a_malformed_file_yields_the_fallback_when_not_throwing(config_file, call, expected):
    config_file(MALFORMED)

    assert call() == expected


@pytest.mark.parametrize("value, expected", [(True, 1), (7, 7), (" 12 ", 12)])
def test_overlay_integers_coerce_bools_ints_and_text(config_file, value, expected):
    config_file("[S]\n")
    settings.set_value("S", "port", value)

    assert settings.get_integer_value("S", "port") == expected


@pytest.mark.parametrize("getter", [settings.get_path_value, settings.get_list_value])
def test_an_unset_path_or_list_returns_the_default(config_file, getter):
    config_file("[S]\n")

    assert getter("Nowhere", "nothing") is None


@pytest.mark.parametrize("getter", [settings.get_path_value, settings.get_list_value])
def test_a_non_text_path_or_list_value_raises(config_file, getter):
    config_file("[S]\n")
    settings.set_value("S", "field", 5)

    with pytest.raises(RuntimeError):
        getter("S", "field")


@pytest.mark.parametrize("getter", [settings.get_path_value, settings.get_list_value])
def test_a_non_text_path_or_list_value_falls_back_when_not_throwing(config_file, getter):
    config_file("[S]\n")
    settings.set_value("S", "field", 5)

    assert getter("S", "field", default_value = "d", throw_exception = False) == "d"


def test_a_non_boolean_overlay_value_raises(config_file):
    config_file("[S]\n")
    settings.set_value("S", "flag", "perhaps")

    with pytest.raises(RuntimeError):
        settings.get_bool_value("S", "flag")
