# Local imports
from joybox import programcatalog
from joybox.tools import firefox


###########################################################
# The tool's config
###########################################################

def test_a_blank_setting_uses_the_profile_firefox_opens(isolated_settings, monkeypatch):
    isolated_settings.set_value("Tools.Firefox", "firefox_profile_dir", "")
    monkeypatch.setattr(programcatalog, "find_default_profile_dir", lambda: "/found/profile")

    assert firefox.Firefox().get_config()["Firefox"]["profile_dir"] == "/found/profile"


def test_a_set_profile_wins_over_the_one_found(isolated_settings, monkeypatch, tmp_path):
    isolated_settings.set_value("Tools.Firefox", "firefox_profile_dir", str(tmp_path))
    monkeypatch.setattr(programcatalog, "find_default_profile_dir", lambda: "/found/profile")

    assert firefox.Firefox().get_config()["Firefox"]["profile_dir"] == str(tmp_path)
