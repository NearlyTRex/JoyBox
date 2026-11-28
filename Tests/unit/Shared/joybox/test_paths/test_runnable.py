# Local imports
from joybox import paths


###########################################################
# Runnable commands
###########################################################

def test_a_command_on_the_path_is_runnable():
    assert paths.is_runnable_command("sh") is True


def test_a_nonexistent_command_is_not_runnable():
    assert paths.is_runnable_command("definitely-not-a-real-binary") is False


def test_a_runnable_command_resolves_to_a_path():
    resolved = paths.get_runnable_command_path("sh")

    assert resolved and resolved.endswith("sh")


def test_an_unresolvable_command_has_no_path():
    assert paths.get_runnable_command_path("definitely-not-a-real-binary") is None


def test_a_search_directory_is_tried_before_the_path(tmp_path):
    local = tmp_path / "sh"
    local.write_text("#!/bin/sh\n")
    local.chmod(0o755)

    resolved = paths.get_runnable_command_path("sh", search_dirs = [str(tmp_path)])

    assert resolved == str(local)


def test_an_empty_search_directory_falls_back_to_the_path(tmp_path):
    assert paths.get_runnable_command_path("sh", search_dirs = [str(tmp_path)]) == \
        paths.get_runnable_command_path("sh")
