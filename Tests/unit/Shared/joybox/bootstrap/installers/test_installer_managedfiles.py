# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox.bootstrap.installers import installer_managedfiles
from fakes import RecordingConnection


###########################################################
# Managed files
#
# Files under a Bootstrap folder are rendered to their destinations. Only the
# active files are deployed and the rest removed; changed files restart their
# service when that is safe, and otherwise the user is told what to restart.
###########################################################

class Sample(installer_managedfiles.ManagedFiles):
    label = "Sample configuration"
    data_folder = "sample"
    files = (
        ("one.conf", "~/.config/sample/one.conf", "sample"),
        ("two.lua", "~/.local/share/sample/two.lua", "sample-helper"),
    )
    safe_services = ("sample-helper",)
    active = ("one.conf", "two.lua")

    def get_active_files(self):
        return list(self.active)

    def render(self, name, contents):
        return contents.replace("1", "one")


class Plain(installer_managedfiles.ManagedFiles):
    label = "Plain configuration"
    data_folder = "sample"
    files = Sample.files


class UnwritableConnection(RecordingConnection):
    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        return False


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    target = tmp_path / "Bootstrap"
    (target / "sample").mkdir(parents = True)
    (target / "sample" / "one.conf").write_text("one = 1\n")
    (target / "sample" / "two.lua").write_text("two = 2\n")
    monkeypatch.setattr(installer_managedfiles.bootstrap, "get_data_dir", lambda: str(target))
    return target / "sample"


def make(connection = None, active = None):
    connection = connection if connection is not None else RecordingConnection()
    sample = Sample(connection)
    if active is not None:
        sample.active = active
    return sample, connection


def test_destinations_expand_the_home(isolated_settings, data_dir):
    sample, _ = make()

    assert sample.get_destinations() == [
        os.path.expanduser("~/.config/sample/one.conf"),
        os.path.expanduser("~/.local/share/sample/two.lua")]


def test_install_writes_each_rendered_file_to_its_destination(isolated_settings, data_dir):
    sample, connection = make()

    assert sample.install()
    one, two = sample.get_destinations()
    assert connection.written(one) == "one = one\n"
    assert connection.written(two) == "two = 2\n"


def test_the_base_installer_deploys_every_file_unchanged(isolated_settings, data_dir):
    connection = RecordingConnection()
    plain = Plain(connection)

    assert plain.get_active_files() == ["one.conf", "two.lua"]
    assert plain.install()
    assert connection.written(plain.get_destinations()[0]) == "one = 1\n"


def test_inactive_files_are_removed(isolated_settings, data_dir):
    sample, connection = make(active = ("one.conf",))
    one, two = sample.get_destinations()
    connection.existing_paths.add(two)

    assert sample.install()
    assert connection.written(one) == "one = one\n"
    assert connection.removed_paths == [two]
    assert sample.is_installed()


def test_a_missing_source_fails_the_install(isolated_settings, data_dir):
    (data_dir / "two.lua").unlink()
    sample, _ = make()

    assert not sample.install()


def test_an_unwritable_destination_fails_the_install(isolated_settings, data_dir):
    sample, _ = make(UnwritableConnection())

    assert not sample.install()


def test_installed_needs_every_destination_to_match(isolated_settings, data_dir):
    sample, connection = make()
    one, two = sample.get_destinations()
    assert not sample.is_installed()

    connection.existing_paths.update([one, two])
    connection.file_contents[one] = "one = one\n"
    connection.file_contents[two] = "two = changed\n"
    assert not sample.is_installed()

    connection.file_contents[two] = "two = 2\n"
    assert sample.is_installed()


def test_install_restarts_safe_services_and_names_the_rest(isolated_settings, data_dir, monkeypatch):
    warnings = []
    monkeypatch.setattr(installer_managedfiles.logger, "log_warning", warnings.append)
    sample, connection = make()

    assert sample.install()
    assert connection.command_strings() == ["systemctl --user restart sample-helper"]
    assert warnings == ["Quit Discord and other voice apps, then apply it with: systemctl --user restart sample"]


def test_unchanged_files_restart_nothing(isolated_settings, data_dir):
    sample, connection = make()
    assert sample.install()
    connection.commands.clear()

    assert sample.install()
    assert connection.commands == []


def test_uninstall_removes_only_present_destinations(isolated_settings, data_dir):
    sample, connection = make()
    _, two = sample.get_destinations()
    connection.existing_paths.add(two)

    assert sample.uninstall()
    assert connection.removed_paths == [two]
    assert connection.command_strings() == ["systemctl --user restart sample-helper"]
