# Local imports
from joybox import network


###########################################################
# Downloading
###########################################################

def test_a_download_follows_redirects(installed, recording_command, tmp_path):
    # Nearly every release link is a redirect to a CDN, and without -L the
    # downloaded file is the redirect page.
    target = tmp_path / "file.bin"
    target.write_text("payload")

    network.download_url("https://example.test/file.bin", output_file = str(target))

    assert "-L" in recording_command.only()


def test_a_download_to_a_file_names_the_output(installed, recording_command, tmp_path):
    target = tmp_path / "file.bin"
    target.write_text("payload")

    assert network.download_url("https://example.test/file.bin", output_file = str(target)) is True
    assert recording_command.value_after("--output") == str(target)


def test_a_download_to_a_directory_keeps_the_remote_name(installed, recording_command, tmp_path):
    target = tmp_path / "downloads"
    target.mkdir()
    (target / "file.bin").write_text("payload")

    assert network.download_url("https://example.test/file.bin", output_dir = str(target)) is True
    assert recording_command.value_after("--output-dir") == str(target)
    assert "-O" in recording_command.only()


def test_a_download_that_wrote_nothing_reports_failure(installed, recording_command, tmp_path):
    # Curl can return zero and leave no file, and the caller would then read a
    # path that is not there.
    assert network.download_url(
        "https://example.test/file.bin",
        output_file = str(tmp_path / "absent.bin")) is False


def test_a_download_to_a_directory_without_the_file_reports_failure(installed, recording_command, tmp_path):
    target = tmp_path / "downloads"
    target.mkdir()

    assert network.download_url("https://example.test/file.bin", output_dir = str(target)) is False


def test_a_download_with_no_destination_reports_failure(installed, recording_command):
    assert network.download_url("https://example.test/file.bin") is False


def test_a_failed_download_reports_failure(installed, monkeypatch, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)
    target = tmp_path / "file.bin"
    target.write_text("payload")

    assert network.download_url("https://example.test/file.bin", output_file = str(target)) is False


def test_downloading_without_curl_reports_failure(missing, recording_command):
    assert network.download_url("https://example.test/file.bin", output_file = "/tmp/file.bin") is False
    assert recording_command.ran() is False


###########################################################
# Cloning
###########################################################

def test_a_clone_brings_its_submodules(installed, recording_command, tmp_path):
    # A repository cloned without submodules is missing the tools it vendors.
    target = tmp_path / "repo"
    target.mkdir()

    network.download_git_url("https://example.test/repo.git", str(target))

    assert "--recursive" in recording_command.only()


def test_a_clone_can_leave_submodules_out(installed, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    network.download_git_url("https://example.test/repo.git", str(target), recursive = False)

    assert "--recursive" not in recording_command.only()


def test_a_clone_can_name_a_branch(installed, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    network.download_git_url("https://example.test/repo.git", str(target), branch = "stable")

    assert recording_command.value_after("--branch") == "stable"


def test_a_fork_is_cloned_from_its_configured_branch(installed, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    network.download_github_repository("NearlyTRex", "Nile", github_branch = "dev", output_dir = str(target))

    assert recording_command.value_after("--branch") == "dev"


def test_a_fork_without_a_branch_uses_its_default(installed, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    network.download_github_repository("NearlyTRex", "Nile", output_dir = str(target))

    assert "--branch" not in recording_command.only()


def test_a_clone_names_the_url_and_destination_last(installed, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    network.download_git_url("https://example.test/repo.git", str(target))

    assert recording_command.only()[-2:] == ["https://example.test/repo.git", str(target)]


def test_a_populated_destination_is_not_cloned_over(installed, recording_command, tmp_path):
    # Cloning into a checkout that already has work in it would fail anyway,
    # and the caller only wants the repository present.
    target = tmp_path / "repo"
    target.mkdir()
    (target / "README.md").write_text("already here")

    assert network.download_git_url("https://example.test/repo.git", str(target)) is True
    assert recording_command.ran() is False


def test_a_clean_clone_empties_the_destination_first(installed, recording_command, monkeypatch, tmp_path):
    emptied = []
    monkeypatch.setattr(
        network.fileops, "remove_directory_contents",
        lambda src, **kwargs: emptied.append(src) or True)
    monkeypatch.setattr(network.fileops, "chmod_file_or_directory", lambda **kwargs: True)
    target = tmp_path / "repo"
    target.mkdir()
    (target / "README.md").write_text("stale")

    network.download_git_url("https://example.test/repo.git", str(target), clean = True)

    assert emptied == [str(target)]


def test_a_first_clean_clone_has_nothing_to_clear(installed, recording_command, monkeypatch, tmp_path):
    # The destination does not exist yet on a first clone, and clearing it
    # would ask for permissions on a path that is not there.
    def fail(**kwargs):
        raise AssertionError("there is nothing to clear before a first clone")

    monkeypatch.setattr(network.fileops, "chmod_file_or_directory", fail)
    monkeypatch.setattr(network.fileops, "remove_directory_contents", fail)

    network.download_git_url(
        "https://example.test/repo.git", str(tmp_path / "absent"), clean = True)

    assert recording_command.ran() is True


def test_a_clone_that_produced_nothing_reports_failure(installed, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    assert network.download_git_url("https://example.test/repo.git", str(target)) is False


def test_a_failed_clone_reports_failure(installed, monkeypatch, tmp_path):
    from fakes import RecordingCommand
    RecordingCommand(monkeypatch, returncode = 1)
    target = tmp_path / "repo"
    target.mkdir()

    assert network.download_git_url("https://example.test/repo.git", str(target)) is False


def test_cloning_without_git_reports_failure(missing, recording_command, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()

    assert network.download_git_url("https://example.test/repo.git", str(target)) is False
    assert recording_command.ran() is False


def test_a_download_ignores_unrelated_files_beside_it(installed, recording_command, tmp_path):
    target = tmp_path / "downloads"
    target.mkdir()
    (target / "other.txt").write_text("unrelated")
    (target / "nested.bin").mkdir()

    assert network.download_url("https://example.test/file.bin", output_dir = str(target)) is False


def test_a_download_creates_its_destination_directory(installed, recording_command, tmp_path):
    target = tmp_path / "fresh"

    network.download_url("https://example.test/file.bin", output_dir = str(target))

    assert target.is_dir()


def test_a_pretend_download_reports_success(installed, recording_command, tmp_path):
    # Nothing was written, and the steps after it still need to be walked through.
    assert network.download_url(
        "https://example.test/file.bin",
        output_file = str(tmp_path / "absent.bin"),
        pretend_run = True) is True


def test_a_pretend_clone_reports_success(installed, recording_command, tmp_path):
    assert network.download_git_url(
        "https://example.test/repo.git", str(tmp_path / "absent"), pretend_run = True) is True


def test_a_clone_runs_from_the_home_directory(installed, recording_command, tmp_path):
    network.download_git_url("https://example.test/repo.git", str(tmp_path / "repo"))

    assert recording_command.options().get_cwd() == network.os.path.expanduser("~")
