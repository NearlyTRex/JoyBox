# Imports
import os
import pytest

# Local imports
from joybox.connection import ConnectionLocal


###########################################################
# Local home resolution
#
# The local transport probes paths with os.path.exists, which takes ~ as an
# ordinary directory name. Resolution has to happen before the probe or every
# candidate reports missing and the write lands on a literal ~ path.
###########################################################

@pytest.fixture
def local_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def connection(local_home):
    conn = ConnectionLocal()
    conn.get_flags().verbose = False
    conn.get_flags().exit_on_failure = False
    return conn


def test_the_local_home_is_the_running_users_home(connection, local_home):
    assert connection.get_home_directory() == str(local_home)


def test_the_local_separator_matches_the_host(connection):
    assert connection.get_path_separator() == os.sep


def test_a_resolved_home_path_is_found_on_disk(connection, local_home):
    (local_home / ".bashrc").write_text("# existing\n")

    resolved = connection.resolve_home_path("~/.bashrc")
    assert connection.does_file_or_directory_exist(resolved) is True


def test_an_unresolved_home_path_is_not_found_on_disk(connection, local_home):
    # The reason resolution is needed at all.
    (local_home / ".bashrc").write_text("# existing\n")

    assert connection.does_file_or_directory_exist("~/.bashrc") is False


def test_the_path_is_exported_into_the_real_profile(connection, local_home):
    (local_home / ".bashrc").write_text("# existing\n")

    assert connection.add_to_unix_path("/opt/tool/bin") is True
    content = (local_home / ".bashrc").read_text()
    assert 'export PATH="/opt/tool/bin:$PATH"' in content
    assert "# existing" in content


def test_no_literal_tilde_directory_is_created(connection, local_home, tmp_path):
    (local_home / ".bashrc").write_text("# existing\n")
    connection.add_to_unix_path("/opt/tool/bin")

    assert not (tmp_path / "~").exists()
    assert not (local_home / "~").exists()


def test_the_first_present_profile_is_used(connection, local_home):
    (local_home / ".bashrc").write_text("")
    (local_home / ".zshrc").write_text("")
    connection.add_to_unix_path("/opt/tool/bin")

    assert "/opt/tool/bin" in (local_home / ".bashrc").read_text()
    assert (local_home / ".zshrc").read_text() == ""


def test_bash_profile_wins_over_bashrc(connection, local_home):
    # The candidate order is login precedence, not alphabetical.
    (local_home / ".bash_profile").write_text("")
    (local_home / ".bashrc").write_text("")
    connection.add_to_unix_path("/opt/tool/bin")

    assert "/opt/tool/bin" in (local_home / ".bash_profile").read_text()
    assert (local_home / ".bashrc").read_text() == ""


def test_an_already_exported_path_is_not_added_twice(connection, local_home):
    (local_home / ".bashrc").write_text('export PATH="/opt/tool/bin:$PATH"\n')
    connection.add_to_unix_path("/opt/tool/bin")

    assert (local_home / ".bashrc").read_text().count("/opt/tool/bin") == 1


def test_adding_two_paths_keeps_both(connection, local_home):
    (local_home / ".bashrc").write_text("")
    connection.add_to_unix_path("/opt/first/bin")
    connection.add_to_unix_path("/opt/second/bin")

    content = (local_home / ".bashrc").read_text()
    assert "/opt/first/bin" in content
    assert "/opt/second/bin" in content


def test_pretending_writes_no_profile(connection, local_home):
    (local_home / ".bashrc").write_text("# existing\n")
    connection.get_flags().pretend_run = True

    assert connection.add_to_unix_path("/opt/tool/bin") is True
    assert (local_home / ".bashrc").read_text() == "# existing\n"
