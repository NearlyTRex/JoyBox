# Imports
import sys
import pytest

# Local imports
from joybox import arguments, config


###########################################################
# Argument parsing
#
# Every script's entry point. A safety flag that parses as unknown is dropped
# silently, so --pretend-run would run for real.
###########################################################

@pytest.fixture
def argv(monkeypatch):
    def set_argv(*values):
        monkeypatch.setattr(sys, "argv", ["script.py"] + list(values))
    set_argv()
    return set_argv


def build(description = "Test parser"):
    return arguments.ArgumentParser(description = description)


###########################################################
# Option aliases
#
# Long options are declared with underscores, and a hyphen is the more natural
# thing to type. Both have to reach the same destination.
###########################################################

def test_the_declared_form_is_accepted(argv):
    parser = build()
    parser.add_boolean_argument(args = ("-p", "--pretend_run"))
    argv("--pretend_run")

    assert parser.parse_args().pretend_run is True


def test_the_hyphen_form_is_accepted(argv):
    # A mistyped safety flag must not be dropped as unknown.
    parser = build()
    parser.add_boolean_argument(args = ("-p", "--pretend_run"))
    argv("--pretend-run")

    assert parser.parse_args().pretend_run is True


def test_a_hyphenated_declaration_accepts_the_underscore_form(argv):
    parser = build()
    parser.add_boolean_argument(args = ("--no-preview",))
    argv("--no_preview")

    assert parser.parse_args().no_preview is True


def test_the_short_form_still_works(argv):
    parser = build()
    parser.add_boolean_argument(args = ("-p", "--pretend_run"))
    argv("-p")

    assert parser.parse_args().pretend_run is True


def test_both_forms_reach_the_same_destination(argv):
    parser = build()
    parser.add_string_argument(args = ("--game_name",))
    argv("--game-name", "Chrono Trigger")

    assert parser.parse_args().game_name == "Chrono Trigger"


@pytest.mark.parametrize("args,expected", [
    (("--pretend_run",), ("--pretend_run", "--pretend-run")),
    (("--no-preview",), ("--no-preview", "--no_preview")),
    (("-p", "--pretend_run"), ("-p", "--pretend_run", "--pretend-run")),
    (("--verbose",), ("--verbose",)),
    (("-v",), ("-v",)),
    (("input_path",), ("input_path",)),
])
def test_alias_expansion(args, expected):
    assert build()._expand_arg_aliases(args) == expected


def test_a_short_option_gains_no_alias():
    assert build()._expand_arg_aliases(("-p",)) == ("-p",)


def test_an_already_paired_declaration_gains_nothing():
    expanded = build()._expand_arg_aliases(("--pretend_run", "--pretend-run"))

    assert expanded == ("--pretend_run", "--pretend-run")


def test_a_bare_string_declaration_is_accepted():
    assert build()._expand_arg_aliases("--pretend_run") == \
        ("--pretend_run", "--pretend-run")


###########################################################
# Values
###########################################################

def test_a_string_argument_is_read(argv):
    parser = build()
    parser.add_string_argument(args = ("-n", "--name"))
    argv("--name", "Chrono Trigger")

    assert parser.parse_args().name == "Chrono Trigger"


def test_a_string_argument_falls_back_to_its_default(argv):
    parser = build()
    parser.add_string_argument(args = ("-n", "--name"), default = "fallback")

    assert parser.parse_args().name == "fallback"


def test_an_integer_argument_is_parsed(argv):
    parser = build()
    parser.add_integer_argument(args = ("-c", "--count"))
    argv("--count", "42")

    assert parser.parse_args().count == 42


def test_a_non_integer_is_refused(argv):
    parser = build()
    parser.add_integer_argument(args = ("-c", "--count"))
    argv("--count", "abc")

    with pytest.raises(SystemExit):
        parser.parse_args()


def test_a_boolean_argument_defaults_to_off(argv):
    parser = build()
    parser.add_boolean_argument(args = ("-v", "--verbose"))

    assert parser.parse_args().verbose is False


def test_a_string_list_argument_accumulates(argv):
    parser = build()
    parser.add_string_list_argument(args = ("-e", "--exclude"))
    argv("--exclude", "one", "--exclude", "two")

    assert parser.parse_args().exclude == ["one", "two"]


def test_a_missing_required_argument_is_refused(argv):
    parser = build()
    parser.add_string_argument(args = ("-n", "--name"), required = True)

    with pytest.raises(SystemExit):
        parser.parse_args()


###########################################################
# Enums
###########################################################

def test_an_enum_argument_becomes_a_member(argv):
    parser = build()
    parser.add_enum_argument(args = ("-t", "--locker_type"), arg_type = config.LockerType)
    argv("--locker_type", str(config.LockerType.LOCAL))

    assert parser.parse_args().locker_type == config.LockerType.LOCAL


def test_an_enum_default_is_kept(argv):
    parser = build()
    parser.add_enum_argument(
        args = ("-t", "--locker_type"),
        arg_type = config.LockerType,
        default = config.LockerType.LOCAL)

    assert parser.parse_args().locker_type == config.LockerType.LOCAL


def test_an_unknown_enum_value_is_refused(argv):
    # argparse rejects it against the choices before the action runs.
    parser = build()
    parser.add_enum_argument(args = ("-t", "--locker_type"), arg_type = config.LockerType)
    argv("--locker_type", "not-a-locker")

    with pytest.raises(SystemExit):
        parser.parse_args()


def test_multiple_enum_values_become_members(argv):
    parser = build()
    parser.add_enum_argument(
        args = ("-t", "--locker_types"),
        arg_type = config.LockerType,
        allow_multiple = True)
    argv("--locker_types", str(config.LockerType.LOCAL), str(config.LockerType.EXTERNAL))

    assert parser.parse_args().locker_types == [
        config.LockerType.LOCAL, config.LockerType.EXTERNAL]


def test_multiple_enums_default_to_an_empty_list(argv):
    parser = build()
    parser.add_enum_argument(
        args = ("-t", "--locker_types"),
        arg_type = config.LockerType,
        allow_multiple = True)

    assert parser.parse_args().locker_types == []


def test_a_single_multiple_enum_default_becomes_a_list(argv):
    # Callers iterate the result, so a bare member would iterate its characters.
    parser = build()
    parser.add_enum_argument(
        args = ("-t", "--locker_types"),
        arg_type = config.LockerType,
        allow_multiple = True,
        default = config.LockerType.LOCAL)

    assert parser.parse_args().locker_types == [config.LockerType.LOCAL]


@pytest.mark.parametrize("value,expected", [
    (config.LockerType.LOCAL, config.LockerType.LOCAL),
    (str(config.LockerType.LOCAL), config.LockerType.LOCAL),
    ("not-a-locker", None),
    ("", None),
    (None, None),
])
def test_enum_values_are_parsed(value, expected):
    assert arguments.parse_enum_value(config.LockerType, value) == expected


def test_an_enum_member_is_returned_unchanged():
    member = config.LockerType.LOCAL

    assert arguments.parse_enum_value(config.LockerType, member) is member


###########################################################
# Unknown arguments
###########################################################

def test_an_unknown_flag_is_reported(argv, monkeypatch):
    warnings = []
    monkeypatch.setattr(arguments.logger, "log_warning", warnings.append)
    parser = build()
    argv("--not-a-flag")
    parser.parse_known_args()

    assert warnings and "--not-a-flag" in warnings[0]


def test_an_unknown_flag_is_reported_once(argv, monkeypatch):
    # Several helpers re-parse, and repeating the warning would bury it.
    warnings = []
    monkeypatch.setattr(arguments.logger, "log_warning", warnings.append)
    parser = build()
    argv("--not-a-flag")
    parser.parse_known_args()
    parser.parse_known_args()

    assert len(warnings) == 1


def test_a_positional_leftover_is_not_reported(argv, monkeypatch):
    warnings = []
    monkeypatch.setattr(arguments.logger, "log_warning", warnings.append)
    parser = build()
    argv("leftover")
    parser.parse_known_args()

    assert warnings == []


def test_unknown_arguments_are_returned(argv):
    parser = build()
    argv("--not-a-flag")
    args, unknown = parser.parse_known_args()

    assert unknown == ["--not-a-flag"]


def test_a_known_argument_is_recognised(argv):
    parser = build()
    parser.add_string_argument(args = ("-n", "--name"))

    assert parser.is_known_argument("name") is True
    assert parser.is_known_argument("absent") is False


###########################################################
# Paths
###########################################################

def test_a_path_is_made_absolute(argv, tmp_path):
    parser = build()
    parser.add_input_path_argument()
    argv("--input_path", str(tmp_path))

    assert parser.get_path("input_path") == str(tmp_path.resolve())


def test_a_relative_path_is_resolved(argv, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "games").mkdir()
    parser = build()
    parser.add_input_path_argument()
    argv("--input_path", "games")

    assert parser.get_path("input_path") == str((tmp_path / "games").resolve())


def test_an_unset_path_is_nothing(argv):
    parser = build()
    parser.add_input_path_argument()

    assert parser.get_path("input_path") is None


def test_an_unknown_path_argument_is_nothing(argv):
    parser = build()

    assert parser.get_path("input_path") is None


def test_a_checked_path_is_returned_when_present(argv, tmp_path):
    parser = build()
    parser.add_input_path_argument()
    argv("--input_path", str(tmp_path))

    assert parser.get_checked_path("input_path") == str(tmp_path.resolve())


def test_a_checked_path_that_is_missing_exits(argv, tmp_path, monkeypatch):
    # Every script uses this to fail before it starts work.
    errors = []

    def log_error(message, quit_program = False):
        errors.append(message)
        if quit_program:
            raise SystemExit(1)

    monkeypatch.setattr(arguments.logger, "log_error", log_error)
    parser = build()
    parser.add_input_path_argument()
    argv("--input_path", str(tmp_path / "absent"))

    with pytest.raises(SystemExit):
        parser.get_checked_path("input_path")
    assert errors


def test_input_and_output_paths_are_separate(argv, tmp_path):
    source = tmp_path / "in"
    target = tmp_path / "out"
    source.mkdir()
    target.mkdir()
    parser = build()
    parser.add_input_path_argument()
    parser.add_output_path_argument()
    argv("--input_path", str(source), "--output_path", str(target))

    assert parser.get_input_path() == str(source.resolve())
    assert parser.get_output_path() == str(target.resolve())


###########################################################
# Category selection
###########################################################

def test_no_supercategory_selects_roms(argv):
    # Unlike the category argument, this one carries a default, so the "select
    # everything" fallback below it is never reached through the helper.
    parser = build()
    parser.add_game_supercategory_argument()

    assert parser.get_selected_supercategories() == [config.Supercategory.ROMS]


def test_an_undeclared_supercategory_selects_them_all(argv):
    parser = build()

    assert parser.get_selected_supercategories() == config.Supercategory.members()


def test_a_supercategory_narrows_the_selection(argv):
    parser = build()
    parser.add_game_supercategory_argument()
    argv("--game_supercategory", str(config.Supercategory.ROMS))

    assert parser.get_selected_supercategories() == [config.Supercategory.ROMS]


def test_no_category_selects_them_all(argv):
    parser = build()
    parser.add_game_category_argument()

    assert parser.get_selected_categories() == config.Category.members()


def test_a_category_narrows_the_selection(argv):
    parser = build()
    parser.add_game_category_argument()
    argv("--game_category", str(config.Category.NINTENDO))

    assert parser.get_selected_categories() == [config.Category.NINTENDO]


def test_no_subcategory_selects_every_one_of_each_category(argv):
    parser = build()
    parser.add_game_category_argument()
    parser.add_game_subcategory_argument()
    argv("--game_category", str(config.Category.NINTENDO))
    selected = parser.get_selected_subcategories()

    assert list(selected) == [config.Category.NINTENDO]
    assert selected[config.Category.NINTENDO] == \
        config.subcategory_map[config.Category.NINTENDO]


def test_a_subcategory_narrows_its_category(argv):
    parser = build()
    parser.add_game_category_argument()
    parser.add_game_subcategory_argument()
    argv("--game_category", str(config.Category.NINTENDO),
         "--game_subcategory", str(config.Subcategory.NINTENDO_NES))
    selected = parser.get_selected_subcategories()

    assert selected == {config.Category.NINTENDO: [config.Subcategory.NINTENDO_NES]}


def test_every_category_is_mapped_when_none_is_given(argv):
    parser = build()
    parser.add_game_category_argument()
    parser.add_game_subcategory_argument()
    selected = parser.get_selected_subcategories()

    assert set(selected) == set(config.Category.members())


###########################################################
# Common arguments
###########################################################

COMMON = ["verbose", "pretend_run", "exit_on_failure", "no_preview"]


@pytest.mark.parametrize("name", COMMON)
def test_every_common_argument_is_declared(argv, name):
    parser = build()
    parser.add_common_arguments()

    assert parser.is_known_argument(name) is True


@pytest.mark.parametrize("name", COMMON)
def test_every_common_argument_defaults_to_off(argv, name):
    parser = build()
    parser.add_common_arguments()

    assert getattr(parser.parse_args(), name) is False


@pytest.mark.parametrize("flag,name", [
    ("--verbose", "verbose"),
    ("--pretend_run", "pretend_run"),
    ("--pretend-run", "pretend_run"),
    ("--exit_on_failure", "exit_on_failure"),
    ("--exit-on-failure", "exit_on_failure"),
    ("--no-preview", "no_preview"),
    ("--no_preview", "no_preview"),
])
def test_every_common_flag_is_accepted_in_both_forms(argv, flag, name):
    parser = build()
    parser.add_common_arguments()
    argv(flag)

    assert getattr(parser.parse_args(), name) is True


def test_common_short_flags_do_not_collide(argv):
    parser = build()
    parser.add_common_arguments()
    argv("-v", "-p", "-x")
    args = parser.parse_args()

    assert args.verbose is True
    assert args.pretend_run is True
    assert args.exit_on_failure is True


###########################################################
# Description
#
# The command reference is generated from describe(), so it has to report what
# was declared: no aliases, the description without decoration, and each
# option under the group it was added to.
###########################################################

def describe_options(parser):
    return {option["dest"]: option for group in parser.describe()["groups"] for option in group["options"]}


def test_describe_reports_the_declared_flags_only():
    parser = build()
    parser.add_boolean_argument(args = ("-p", "--pretend_run"), description = "Pretend")

    assert describe_options(parser)["pretend_run"]["flags"] == ["-p", "--pretend_run"]


def test_describe_reports_an_enum_description_without_its_value_list():
    parser = build()
    parser.add_enum_argument(args = ("-c", "--game_category"), arg_type = config.Category, description = "Category")

    option = describe_options(parser)["game_category"]

    assert option["description"] == "Category"
    assert option["choices"] == config.Category.values()


def test_describe_reports_an_enum_default_as_its_display_value():
    parser = build()
    parser.add_game_supercategory_argument()

    assert describe_options(parser)["game_supercategory"]["default"] == str(config.Supercategory.ROMS)


def test_describe_places_options_in_their_group():
    parser = build()
    parser.add_string_argument(args = ("-n", "--name"), description = "Name")
    parser.add_group("Output")
    parser.add_string_argument(args = ("-o", "--output_path"), description = "Output")

    groups = parser.describe()["groups"]

    assert [(group["title"], [option["dest"] for option in group["options"]]) for group in groups] == \
        [(None, ["name"]), ("Output", ["output_path"])]


def test_common_arguments_do_not_capture_later_options():
    parser = build()
    parser.add_common_arguments()
    parser.add_string_argument(args = ("-n", "--name"), description = "Name")

    groups = {group["title"]: [option["dest"] for option in group["options"]] for group in parser.describe()["groups"]}

    assert groups[None] == ["name"]
    assert "name" not in groups["Common options"]


def test_describe_leaves_out_help():
    assert "help" not in describe_options(build())


def test_a_positional_without_a_default_is_required():
    parser = build()
    parser.add_string_argument(args = ("name",), description = "Name")

    option = describe_options(parser)["name"]

    assert option["positional"] and option["required"]


def test_describe_carries_the_page_fields():
    parser = arguments.ArgumentParser(
        description = "Tool",
        details = "More",
        examples = [("Run it", "tool -x")],
        notes = ["Careful"],
        see_also = ["other"],
        section = "Section")

    described = parser.describe()

    assert (described["details"], described["examples"], described["notes"], described["see_also"], described["section"]) == \
        ("More", [["Run it", "tool -x"]], ["Careful"], ["other"], "Section")


def test_help_shows_examples_on_their_own_lines(argv, capsys):
    parser = arguments.ArgumentParser(description = "Tool", examples = [("Run it", "tool --flag value")])
    argv("--help")

    with pytest.raises(SystemExit):
        parser.parse_args()

    assert "\n  tool --flag value\n" in capsys.readouterr().out


def test_help_leaves_out_an_empty_default(argv, capsys):
    parser = build()
    parser.add_string_argument(args = ("-n", "--name"), description = "Name")
    argv("--help")

    with pytest.raises(SystemExit):
        parser.parse_args()

    assert "default: None" not in capsys.readouterr().out
