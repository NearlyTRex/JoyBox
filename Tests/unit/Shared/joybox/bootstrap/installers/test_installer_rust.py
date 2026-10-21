# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_rust
from fakes import RecordingConnection


###########################################################
# Rust (rustup toolchain, targets and cargo-installed crates)
###########################################################

XWIN = {"id": "xwin", "name": "xwin", "description": "sdk", "category": "Devel"}
MSVC = {"id": "x86_64-pc-windows-msvc", "name": "Windows MSVC", "description": "target", "category": "Devel"}
INSTALLED_TARGETS = {"target list --installed": "x86_64-unknown-linux-gnu\nx86_64-pc-windows-msvc\n"}


def make(packages, targets = (), **kwargs):
    connection = RecordingConnection(**kwargs)
    rust = installers.Rust(connection)
    rust.get_packages = lambda: list(packages)
    rust.get_targets = lambda: list(targets)
    return rust, connection


def binary(rust, name):
    return rust.cargo_bin_dir + "/" + name


def test_package_descriptors_fall_back_sensibly():
    assert installer_rust.get_cargo_package_id({"name": "ripgrep"}) == "ripgrep"
    assert installer_rust.get_cargo_package_id({}) == ""
    assert installer_rust.get_cargo_package_info({"id": "ripgrep", "binary": "rg"}) == {
        "id": "ripgrep", "name": "ripgrep", "description": "", "category": "", "binary": "rg"}
    assert installer_rust.get_cargo_package_info(XWIN)["binary"] == "xwin"


def test_only_local_ubuntu_is_supported(isolated_settings):
    rust, _ = make([])
    assert rust.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_the_lists_follow_the_environment_type(isolated_settings):
    rust = installers.Rust(RecordingConnection())
    rust.set_environment_type(constants.EnvironmentType.LOCAL_UBUNTU)

    assert rust.get_packages() == installer_rust.packages.cargo[constants.EnvironmentType.LOCAL_UBUNTU]
    assert rust.get_targets() == installer_rust.packages.rust_targets[constants.EnvironmentType.LOCAL_UBUNTU]
    assert {"xwin", "cargo-xwin"} <= {pkg["id"] for pkg in rust.get_packages()}
    assert "x86_64-pc-windows-msvc" in [target["id"] for target in rust.get_targets()]


def test_installed_needs_the_toolchain_every_target_and_every_crate(isolated_settings):
    rust, connection = make([XWIN], [MSVC])
    assert not rust.is_installed()
    assert rust.get_package_status() == {"installed": [], "missing": ["rust", "Windows MSVC", "xwin"]}
    assert not connection.ran("target list")

    connection.existing_paths.add(rust.cargo_tool)
    assert not rust.is_installed()
    assert rust.get_package_status() == {"installed": ["rust"], "missing": ["Windows MSVC", "xwin"]}

    connection.command_output.update(INSTALLED_TARGETS)
    assert not rust.is_installed()
    assert rust.get_package_status() == {"installed": ["rust", "Windows MSVC"], "missing": ["xwin"]}

    connection.existing_paths.add(binary(rust, "xwin"))
    assert rust.is_installed()
    assert rust.get_package_status() == {"installed": ["rust", "Windows MSVC", "xwin"], "missing": []}


def test_install_runs_rustup_then_adds_targets_and_installs_crates(isolated_settings):
    rust, connection = make([XWIN], [MSVC])
    rust.is_toolchain_installed = iter([False, True]).__next__

    assert rust.install()
    assert connection.downloads == [("https://sh.rustup.rs", "/tmp/rustup_install.sh")]
    assert connection.ran("sh /tmp/rustup_install.sh -y")
    assert connection.ran(rust.rustup_tool, "target add x86_64-pc-windows-msvc")
    assert connection.ran(rust.cargo_tool, "install --locked xwin")


def test_install_updates_an_existing_toolchain_and_skips_what_is_there(isolated_settings):
    rust, connection = make([XWIN], [MSVC], command_output = INSTALLED_TARGETS)
    connection.existing_paths.update([rust.cargo_tool, binary(rust, "xwin")])

    assert rust.install()
    assert connection.downloads == []
    assert connection.ran(rust.rustup_tool, "update stable")
    assert not connection.ran("target add")
    assert not connection.ran("install --locked")


def test_a_failed_script_fails_the_install(isolated_settings):
    rust, _ = make([XWIN], return_codes = {"rustup_install.sh": 1})
    assert not rust.install()


def test_install_fails_when_no_toolchain_appears(isolated_settings):
    rust, connection = make([XWIN])
    assert not rust.install()
    assert not connection.ran("install --locked")


def test_a_failed_update_fails_the_install(isolated_settings):
    rust, connection = make([XWIN], return_codes = {"update stable": 1})
    connection.existing_paths.add(rust.cargo_tool)
    assert not rust.install()
    assert not connection.ran("install --locked")


def test_a_failed_target_fails_the_install(isolated_settings):
    rust, connection = make([XWIN], [MSVC], return_codes = {"target add": 1})
    connection.existing_paths.add(rust.cargo_tool)
    assert not rust.install()
    assert not connection.ran("install --locked")


def test_a_failed_crate_fails_the_install(isolated_settings):
    rust, connection = make([XWIN], return_codes = {"install --locked xwin": 101})
    connection.existing_paths.add(rust.cargo_tool)
    assert not rust.install()


def test_uninstall_runs_rustup_self_uninstall(isolated_settings):
    rust, connection = make([XWIN])
    connection.existing_paths.add(rust.rustup_tool)

    assert rust.uninstall()
    assert connection.ran(rust.rustup_tool, "self uninstall -y")


def test_a_failed_self_uninstall_fails_the_uninstall(isolated_settings):
    rust, connection = make([XWIN], return_codes = {"self uninstall": 1})
    connection.existing_paths.add(rust.rustup_tool)
    assert not rust.uninstall()


def test_uninstall_of_nothing_succeeds(isolated_settings):
    rust, connection = make([XWIN])

    assert rust.uninstall()
    assert connection.commands == []
