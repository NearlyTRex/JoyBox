# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_llvm
from fakes import RecordingConnection


###########################################################
# LLVM
#
# apt.llvm.org keeps one repository per Ubuntu release and LLVM version, so
# both pick the sources line and its file name.
###########################################################

CODENAME = "noble"


def make(monkeypatch):
    monkeypatch.setattr(installer_llvm.platform_info, "get_ubuntu_codename", lambda: CODENAME)
    connection = RecordingConnection()
    return installers.Llvm(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings, monkeypatch):
    llvm, _ = make(monkeypatch)
    assert llvm.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_follows_the_versioned_compiler(isolated_settings, monkeypatch):
    llvm, connection = make(monkeypatch)
    assert not llvm.is_installed()

    connection.existing_paths.add(f"/usr/bin/clang++-{installer_llvm.LLVM_VERSION}")
    assert llvm.is_installed()


def test_install_adds_the_release_repository_then_the_toolchain(isolated_settings, monkeypatch):
    llvm, connection = make(monkeypatch)
    version = installer_llvm.LLVM_VERSION
    connection.existing_paths.add(llvm.clang_path)

    assert llvm.install()
    assert connection.downloads == [(f"{llvm.url}/llvm-snapshot.gpg.key", llvm.archive_key_path)]
    assert connection.written(llvm.sources_list) == (
        f"deb [signed-by={llvm.archive_key_path}] {llvm.url}/{CODENAME}/ "
        f"llvm-toolchain-{CODENAME}-{version} main\n")
    assert connection.moved == [(f"/tmp/{llvm.sources_list}", llvm.sources_list_path)]
    assert llvm.sources_list_path == f"/etc/apt/sources.list.d/llvm-toolchain-{CODENAME}-{version}.list"
    assert connection.ran("install -y", f"clang-{version}", f"clang-tidy-{version}",
        f"libc++-{version}-dev", f"libclang-rt-{version}-dev")


def test_install_fails_when_no_compiler_appears(isolated_settings, monkeypatch):
    llvm, _ = make(monkeypatch)
    assert not llvm.install()


def test_uninstall_removes_the_packages_and_the_repository(isolated_settings, monkeypatch):
    llvm, connection = make(monkeypatch)

    assert llvm.uninstall()
    assert connection.ran("remove -y", f"clang-{installer_llvm.LLVM_VERSION}")
    assert connection.removed_paths == [llvm.sources_list_path, llvm.archive_key_path]
