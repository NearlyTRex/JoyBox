# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import sync
from sync_helpers import REMOTE, REMOTE_TYPE, LOCAL, REMOTE_PATH


###########################################################
# Diffing a local tree against a remote
###########################################################

def run_diff(tmp_path, **kwargs):
    defaults = dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE,
        remote_path = REMOTE_PATH, local_path = LOCAL)
    defaults.update(kwargs)
    return sync.diff_files(**defaults)


def excludes_of(cmd):
    return [cmd[index + 1] for index, part in enumerate(cmd) if part == "--exclude"]


@pytest.fixture
def sorted_files(monkeypatch):
    sorted_paths = []
    monkeypatch.setattr(
        sync.fileops, "sort_file_contents",
        lambda src, **kwargs: sorted_paths.append(src) or True)
    return sorted_paths


@pytest.mark.parametrize("excludes,expected", [
    (None, [".*/**"]),
    (["Cache/**"], ["Cache/**", ".*/**"]),
    ([".*/**"], [".*/**"]),
    ("Cache/**", ["Cache/**", ".*/**"]),
    (("Cache/**",), ["Cache/**", ".*/**"]),
])
def test_a_diff_always_leaves_out_hidden_paths(rclone, recording_command, quiet, tmp_path, excludes, expected):
    assert run_diff(tmp_path, excludes = excludes) is True

    assert excludes_of(recording_command.only()) == expected


def test_a_diff_without_report_paths_runs_a_plain_check(rclone, recording_command, quiet, tmp_path):
    run_diff(tmp_path)
    cmd = recording_command.only()

    assert cmd[1:3] == ["check", LOCAL]
    for flag in ["--combined", "--differ", "--missing-on-src", "--missing-on-dst", "--error", "--size-only"]:
        assert flag not in cmd


def test_each_report_path_gets_its_flag(rclone, recording_command, quiet, tmp_path, sorted_files):
    reports = {
        "diff_combined_path": "--combined",
        "diff_intersected_path": "--differ",
        "diff_missing_src_path": "--missing-on-src",
        "diff_missing_dest_path": "--missing-on-dst",
        "diff_error_path": "--error",
    }
    run_diff(tmp_path, **{name: str(tmp_path / name) for name in reports})

    for name, flag in reports.items():
        assert recording_command.value_after(flag) == str(tmp_path / name)


def test_a_quick_diff_compares_sizes_only(rclone, recording_command, quiet, tmp_path):
    run_diff(tmp_path, quick = True)

    assert "--size-only" in recording_command.only()


def test_a_verbose_diff_shows_progress(rclone, recording_command, quiet, tmp_path):
    run_diff(tmp_path, verbose = True)

    assert "--progress" in recording_command.only()


def test_a_diff_without_rclone_is_refused(no_rclone, quiet, recording_command, tmp_path):
    assert run_diff(tmp_path) is False
    assert recording_command.ran() is False


def test_the_combined_report_is_summarised(rclone, recording_command, monkeypatch, tmp_path, sorted_files):
    combined = tmp_path / "combined.txt"
    combined.write_text("= same\n- remote_only\n+ local_only\n* changed\n! broken\n? other\n= also_same\n")
    messages = []
    monkeypatch.setattr(sync.logger, "log_info", lambda message: messages.append(message))
    run_diff(tmp_path, diff_combined_path = str(combined))

    assert "Number of unchanged files: 2" in messages
    assert "Number of changed files: 1" in messages
    assert "Number of error files: 1" in messages
    assert any(message.endswith("only on %s: 1" % LOCAL) for message in messages)
    assert any(message.endswith("%s: 1" % REMOTE_PATH) for message in messages)


def test_every_written_report_is_sorted(rclone, recording_command, quiet, tmp_path, sorted_files):
    written = tmp_path / "differ.txt"
    written.write_text("b\na\n")
    run_diff(
        tmp_path,
        diff_combined_path = str(tmp_path / "never-written.txt"),
        diff_intersected_path = str(written))

    assert sorted_files == [str(written)]


###########################################################
# Diff sync directory handling
###########################################################

@pytest.fixture
def transfers(monkeypatch):
    calls = {"upload": [], "download": [], "recycle": [], "diff": []}

    def recorder(kind):
        def record_call(**kwargs):
            listed = kwargs.get("files_from")
            kwargs["listed"] = open(listed).read() if listed and os.path.exists(listed) else None
            calls[kind].append(kwargs)
            return True
        return record_call

    monkeypatch.setattr(sync, "upload_files_to_remote", recorder("upload"))
    monkeypatch.setattr(sync, "download_files_from_remote", recorder("download"))
    monkeypatch.setattr(sync, "recycle_files_on_remote", recorder("recycle"))
    for name in ["log_info", "log_warning", "log_error"]:
        monkeypatch.setattr(sync.logger, name, lambda *a, **k: None)
    return calls


@pytest.fixture
def generated_diffs(monkeypatch, transfers):
    # Stands in for rclone check, writing the reports it would have
    reports = {}

    def fake_diff(**kwargs):
        transfers["diff"].append(kwargs)
        for key, lines in reports.items():
            with open(kwargs[key], "w") as handle:
                handle.write("".join(line + "\n" for line in lines))
        return True

    monkeypatch.setattr(sync, "diff_files", fake_diff)
    return reports


def run_diff_sync(**kwargs):
    defaults = dict(
        remote_name = REMOTE, remote_type = REMOTE_TYPE,
        remote_path = REMOTE_PATH, local_path = LOCAL)
    defaults.update(kwargs)
    return sync.diff_sync_files(**defaults)


def test_without_a_diff_directory_the_diffs_are_generated(generated_diffs, transfers):
    generated_diffs["diff_missing_dest_path"] = ["new.zip"]

    assert run_diff_sync() is True
    assert transfers["upload"][0]["listed"] == "new.zip"


@pytest.mark.parametrize("diff_dir", [None, ""])
def test_a_generated_diff_directory_is_removed_afterwards(generated_diffs, transfers, diff_dir):
    run_diff_sync(diff_dir = diff_dir)
    used = os.path.dirname(transfers["diff"][0]["diff_combined_path"])

    assert not os.path.exists(used)


def test_a_generated_diff_directory_is_removed_after_a_failure(generated_diffs, transfers, monkeypatch):
    generated_diffs["diff_missing_dest_path"] = ["new.zip"]
    monkeypatch.setattr(sync, "upload_files_to_remote", lambda **kwargs: False)

    assert run_diff_sync() is False
    assert not os.path.exists(os.path.dirname(transfers["diff"][0]["diff_combined_path"]))


def test_a_given_diff_directory_is_read_not_regenerated(generated_diffs, transfers, tmp_path):
    (tmp_path / "diff_missing_src.txt").write_text("onlyremote.zip\n")

    assert run_diff_sync(diff_dir = str(tmp_path)) is True
    assert transfers["diff"] == []
    assert transfers["download"][0]["listed"] == "onlyremote.zip"
    assert (tmp_path / "diff_missing_src.txt").exists()


def test_no_diff_directory_and_no_temporary_one_is_a_failure(transfers, monkeypatch):
    monkeypatch.setattr(sync.fileops, "create_temporary_directory", lambda **kwargs: (False, None))

    assert run_diff_sync() is False


@pytest.mark.parametrize("kind,report,options", [
    ("upload", "diff_missing_dest_path", {}),
    ("download", "diff_missing_src_path", {}),
    ("recycle", "diff_missing_src_path", {"recycle_missing": True}),
])
def test_transfer_lists_are_removed_afterwards(generated_diffs, transfers, kind, report, options):
    generated_diffs[report] = ["game.zip"]
    run_diff_sync(**options)

    assert not os.path.exists(transfers[kind][0]["files_from"])


@pytest.mark.parametrize("report,options", [
    ("diff_missing_dest_path", {}),
    ("diff_missing_src_path", {}),
    ("diff_missing_src_path", {"recycle_missing": True}),
])
def test_a_transfer_list_that_cannot_be_created_stops_the_run(generated_diffs, transfers, monkeypatch, report, options):
    generated_diffs[report] = ["game.zip"]
    monkeypatch.setattr(sync.fileops, "create_temporary_file", lambda **kwargs: (False, None))

    assert run_diff_sync(**options) is False
    assert transfers["upload"] == transfers["download"] == transfers["recycle"] == []


def test_a_transfer_list_that_cannot_be_written_stops_the_run(generated_diffs, transfers, monkeypatch):
    # An empty list would read as nothing to transfer and report success.
    generated_diffs["diff_missing_dest_path"] = ["game.zip"]
    monkeypatch.setattr(sync.serialization, "write_text_file", lambda *args, **kwargs: False)

    assert run_diff_sync() is False
    assert transfers["upload"] == []


@pytest.mark.parametrize("excludes,expected", [
    (None, [".*/**", ".recycle_bin/**"]),
    ("Cache/**", ["Cache/**", ".*/**", ".recycle_bin/**"]),
    ([".*/**", ".recycle_bin/**"], [".*/**", ".recycle_bin/**"]),
    (("Cache/**",), ["Cache/**", ".*/**", ".recycle_bin/**"]),
])
def test_a_diff_sync_leaves_out_hidden_paths_and_the_bin(generated_diffs, transfers, excludes, expected):
    run_diff_sync(excludes = excludes)

    assert transfers["diff"][0]["excludes"] == expected


def test_without_a_recycle_folder_only_hidden_paths_are_left_out(generated_diffs, transfers):
    run_diff_sync(recycle_folder = None)

    assert transfers["diff"][0]["excludes"] == [".*/**"]


def test_the_callers_exclude_list_is_not_modified(generated_diffs, transfers):
    excludes = ["Cache/**"]
    run_diff_sync(excludes = excludes)

    assert excludes == ["Cache/**"]


def test_a_verbose_diff_sync_explains_changed_files(generated_diffs, transfers, monkeypatch):
    generated_diffs["diff_intersected_path"] = ["local.zip", "remote.zip", "unknown.zip"]
    local_times = {"local.zip": 2000, "remote.zip": 1000, "unknown.zip": 0}
    remote_times = {"local.zip": 1000, "remote.zip": 2000, "unknown.zip": 1000}
    monkeypatch.setattr(
        sync.paths, "get_file_mod_time", lambda path: local_times[os.path.basename(path)])
    monkeypatch.setattr(
        sync, "get_path_mod_time",
        lambda remote_path, **kwargs: remote_times[os.path.basename(remote_path)])
    messages = []
    monkeypatch.setattr(sync.logger, "log_info", lambda message: messages.append(message))
    monkeypatch.setattr(sync.logger, "log_warning", lambda message: messages.append(message))

    assert run_diff_sync(verbose = True) is True
    assert "Local is newer: local.zip" in messages
    assert "Remote is newer: remote.zip" in messages
    assert "Could not get modtime for: unknown.zip" in messages
