# Local imports
import joybox.bootstrap.gamemic as gamemic


###########################################################
# Game mic settings
###########################################################

def test_the_shipped_defaults(isolated_settings):
    assert gamemic.get_mode() == gamemic.MODE_SILENT
    assert gamemic.get_allowed_apps() == []
    assert "Discord" in gamemic.get_protected_apps()
    assert gamemic.is_output_locked() is False


def test_the_mode_ignores_case_and_falls_back_to_silent(isolated_settings):
    isolated_settings.set_value(gamemic.SECTION, "game_mic_mode", " Locked ")
    assert gamemic.get_mode() == gamemic.MODE_LOCKED

    isolated_settings.set_value(gamemic.SECTION, "game_mic_mode", "loud")
    assert gamemic.get_mode() == gamemic.MODE_SILENT


def test_app_lists_are_trimmed_and_drop_blanks(isolated_settings):
    isolated_settings.set_value(gamemic.SECTION, "game_mic_allow", " A.exe ,, B.exe ")

    assert gamemic.get_allowed_apps() == ["A.exe", "B.exe"]


def test_name_patterns_ignore_case_and_escape_regex_characters(isolated_settings):
    assert gamemic.get_names_pattern(["Ab 1.x", "c(d)"]) == "^([aA][bB] 1\\.[xX]|[cC]\\([dD]\\))$"


def test_strings_are_quoted_for_each_config_language(isolated_settings):
    assert gamemic.quote_spa_string('a\\b"c') == '"a\\\\b\\"c"'
    assert gamemic.escape_lua_string('a\\b"c\nd') == 'a\\\\b\\"c\\nd'
