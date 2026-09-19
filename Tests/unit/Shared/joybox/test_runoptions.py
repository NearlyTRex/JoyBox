# Imports
import pytest

# Local imports
from joybox import runoptions


###########################################################
# RunFlags / RunOptions
#
# Passed as default arguments throughout the tree, so every caller that omits
# the argument shares one instance. Safe only because consumers store a copy.
###########################################################

def test_flag_defaults():
    flags = runoptions.RunFlags()

    assert flags.verbose is True
    assert flags.exit_on_failure is True
    assert flags.force is False
    assert flags.pretend_run is False
    assert flags.purge_data is False


def test_option_defaults():
    options = runoptions.RunOptions()

    assert options.cwd is None
    assert options.env == {}
    assert options.shell is False
    assert options.include_stderr is False


def test_each_options_instance_gets_its_own_env():
    # A literal {} in the signature would be shared by every instance.
    first = runoptions.RunOptions()
    second = runoptions.RunOptions()
    first.env["JOYBOX"] = "1"

    assert second.env == {}


###########################################################
# Copying
###########################################################

def test_copying_flags_detaches_them():
    original = runoptions.RunFlags()
    duplicate = original.copy()
    duplicate.set(force = True)

    assert original.force is False
    assert duplicate.force is True


def test_copying_options_detaches_nested_state():
    # A shallow copy would share the env dict between consumers.
    original = runoptions.RunOptions(env = {"PATH": "/usr/bin"})
    duplicate = original.copy()
    duplicate.env["PATH"] = "/somewhere/else"

    assert original.env["PATH"] == "/usr/bin"


def test_a_copy_carries_the_current_values():
    original = runoptions.RunFlags(verbose = False, backup_id = "20260101_000000")
    duplicate = original.copy()

    assert duplicate.verbose is False
    assert duplicate.backup_id == "20260101_000000"


###########################################################
# Setting
###########################################################

def test_set_updates_in_place_and_returns_self():
    flags = runoptions.RunFlags()

    assert flags.set(force = True) is flags
    assert flags.force is True


def test_set_accepts_several_fields():
    flags = runoptions.RunFlags().set(force = True, purge_data = True, verbose = False)

    assert flags.force is True
    assert flags.purge_data is True
    assert flags.verbose is False


def test_setting_an_unknown_flag_raises():
    # bootstrap.py forwards CLI arguments through set(); a typo must not pass.
    with pytest.raises(AttributeError):
        runoptions.RunFlags().set(nonexistent = True)


def test_setting_an_unknown_option_raises():
    with pytest.raises(AttributeError):
        runoptions.RunOptions().set(nonexistent = True)


def test_set_on_options_updates_in_place_and_returns_self():
    options = runoptions.RunOptions()

    assert options.set(shell = True) is options
    assert options.shell is True
