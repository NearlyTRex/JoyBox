# Imports
import os
import pytest

# Local imports
from joybox import network


###########################################################
# Archiving
#
# A repository is cloned into a scratch directory, zipped, checked and handed
# to the locker. The scratch directory must go whatever happens, or every run
# leaves a full checkout behind in the temp directory.
###########################################################

@pytest.fixture
def pipeline(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    state = {
        "work": work,
        "temp_ok": True,
        "download_ok": True,
        "write_archive": True,
        "test_ok": True,
        "backup_ok": True,
        "remove_git_ok": True,
        "downloads": [],
        "backups": [],
        "removed": [],
    }

    def create_temporary_directory(**kwargs):
        return (state["temp_ok"], str(work))

    def download_github_repository(**kwargs):
        state["downloads"].append(kwargs)
        return state["download_ok"]

    def create_archive_from_folder(archive_file, **kwargs):
        if state["write_archive"]:
            with open(archive_file, "w") as handle:
                handle.write("zip")

    real_remove_directory = network.fileops.remove_directory

    def remove_directory(src, **kwargs):
        state["removed"].append(src)
        if src.endswith(".git"):
            return state["remove_git_ok"]
        return real_remove_directory(src, **kwargs)

    def backup(**kwargs):
        state["backups"].append(kwargs)
        return state["backup_ok"]

    monkeypatch.setattr(network.fileops, "create_temporary_directory", create_temporary_directory)
    monkeypatch.setattr(network.fileops, "remove_directory", remove_directory)
    monkeypatch.setattr(network, "download_github_repository", download_github_repository)
    monkeypatch.setattr(network.archive, "create_archive_from_folder", create_archive_from_folder)
    monkeypatch.setattr(network.archive, "test_archive", lambda **kwargs: state["test_ok"])
    monkeypatch.setattr(network.locker, "convert_to_relative_path", lambda path: "rel/" + os.path.basename(path))
    monkeypatch.setattr(network.locker, "backup", backup)
    monkeypatch.setattr(network.runtime, "get_current_timestamp", lambda: 1700000000)
    return state


def archive(**kwargs):
    options = {"output_dir": "/locker/Github/NearlyTRex/Nile", "locker_type": "local"}
    options.update(kwargs)
    return network.archive_github_repository("NearlyTRex", "Nile", **options)


def test_an_archived_repository_is_backed_up_under_a_timestamped_name(pipeline):
    assert archive() is True

    backup = pipeline["backups"][0]
    assert backup["dest_rel_path"] == "rel/Nile_1700000000.zip"
    assert backup["src"] == str(pipeline["work"] / "archive" / "tmp.zip")
    assert backup["locker_type"] == "local"


def test_the_clone_lands_in_the_scratch_directory(pipeline):
    archive(github_branch = "dev", recursive = False)

    download = pipeline["downloads"][0]
    assert download["output_dir"] == str(pipeline["work"] / "download")
    assert download["github_branch"] == "dev"
    assert download["recursive"] is False


def test_the_scratch_directory_is_removed_after_success(pipeline):
    archive()

    assert not pipeline["work"].exists()


@pytest.mark.parametrize("failure", ["download_ok", "write_archive", "test_ok", "backup_ok"])
def test_the_scratch_directory_is_removed_after_failure(pipeline, failure):
    pipeline[failure] = False

    assert archive() is False
    assert not pipeline["work"].exists()


def test_no_scratch_directory_means_no_archive(pipeline):
    pipeline["temp_ok"] = False

    assert archive() is False
    assert pipeline["downloads"] == []


def test_a_clean_archive_leaves_out_the_git_history(pipeline):
    assert archive(clean = True) is True

    assert str(pipeline["work"] / "download" / ".git") in pipeline["removed"]


def test_a_git_history_that_cannot_be_removed_fails_the_archive(pipeline):
    pipeline["remove_git_ok"] = False

    assert archive(clean = True) is False
    assert pipeline["backups"] == []


def test_a_pretend_archive_walks_every_step(pipeline):
    # A pretend run writes no archive, so its absence is not a failure.
    pipeline["write_archive"] = False

    assert archive(pretend_run = True) is True
    assert len(pipeline["backups"]) == 1
