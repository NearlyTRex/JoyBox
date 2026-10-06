# Local imports
from joybox.tools import wine


def test_other_platforms_have_no_config(monkeypatch):
    monkeypatch.setattr(wine.platform_info, "is_wine_platform", lambda: False)

    assert wine.Wine().get_config() == {}


def test_programs_live_in_the_install_dir(monkeypatch, isolated_settings):
    monkeypatch.setattr(wine.platform_info, "is_wine_platform", lambda: True)
    isolated_settings.set_value("Tools.Wine", "wine_exe", "wine64")
    isolated_settings.set_value("Tools.Wine", "wine_boot_exe", "wineboot")
    isolated_settings.set_value("Tools.Wine", "wine_server_exe", "wineserver")
    isolated_settings.set_value("Tools.Wine", "wine_tricks_exe", "winetricks")
    isolated_settings.set_value("Tools.Wine", "wine_install_dir", "/opt/wine/bin")
    isolated_settings.set_value("Tools.Wine", "wine_sandbox_dir", "/sandbox")

    tool = wine.Wine()
    config = tool.get_config()

    assert tool.get_name() == "Wine"
    assert config["Wine"] == {"program": "/opt/wine/bin/wine64", "sandbox_dir": "/sandbox"}
    assert config["WineBoot"]["program"] == "/opt/wine/bin/wineboot"
    assert config["WineServer"]["program"] == "/opt/wine/bin/wineserver"
    assert config["WineTricks"]["program"] == "/opt/wine/bin/winetricks"
