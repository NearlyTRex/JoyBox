# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from fakes import RecordingConnection


###########################################################
# SDL3
#
# Built from pinned release tags into /usr/local, where CMake's find_package
# looks; only the install step needs root.
###########################################################

def make(**kwargs):
    connection = RecordingConnection(**kwargs)
    return installers.Sdl3(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    sdl3, _ = make()
    assert sdl3.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_needs_both_libraries(isolated_settings):
    sdl3, _ = make()
    assert sdl3.is_installed()

    sdl3, _ = make(return_codes = {"--exists sdl3-ttf": 1})
    assert not sdl3.is_installed()


def test_install_builds_both_pinned_releases(isolated_settings):
    sdl3, connection = make()

    assert sdl3.install()
    assert connection.ran("clone --depth 1 --branch", sdl3.sdl_tag, sdl3.sdl_repo, sdl3.sdl_src)
    assert connection.ran("clone --depth 1 --branch", sdl3.sdl_ttf_tag, sdl3.sdl_ttf_repo, sdl3.sdl_ttf_src)
    assert connection.ran("-S", sdl3.sdl_src, "-B", sdl3.sdl_build, "-DSDL_SHARED=ON")
    assert connection.ran("-S", sdl3.sdl_ttf_src, "-DSDLTTF_VENDORED=OFF")
    assert connection.ran("ldconfig")


def test_only_the_install_steps_run_as_root(isolated_settings):
    sdl3, connection = make()
    sdl3.install()

    privileged = [call[1][0] for call in connection.called("run_checked") if call[2]["sudo"]]
    assert privileged == [
        [sdl3.cmake_tool, "--install", sdl3.sdl_build],
        [sdl3.cmake_tool, "--install", sdl3.sdl_ttf_build],
        ["ldconfig"]]


def test_the_sources_are_removed_before_and_after(isolated_settings):
    sdl3, connection = make()
    sdl3.install()

    assert connection.removed_paths == [sdl3.sdl_src, sdl3.sdl_src, sdl3.sdl_ttf_src, sdl3.sdl_ttf_src]


def test_uninstall_removes_the_installed_files(isolated_settings):
    sdl3, connection = make()

    assert sdl3.uninstall()
    assert "/usr/local/include/SDL3" in connection.removed_paths
    assert "/usr/local/lib/pkgconfig/sdl3-ttf.pc" in connection.removed_paths
    assert connection.ran("ldconfig")
