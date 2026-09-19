# Imports
import pytest

# Local imports
from joybox import cmdline


###########################################################
# Command string construction
###########################################################

def test_posix_style_quotes_segments_with_spaces():
    built = cmdline.create_command_string(["echo", "hello world"], style = "posix")
    assert built == "echo 'hello world'"


def test_posix_style_escapes_shell_metacharacters():

    # This is the style used for SSH, so a segment that reaches a remote shell
    # unquoted is a command injection, not a formatting problem.
    built = cmdline.create_command_string(["echo", "a; rm -rf /"], style = "posix")
    assert "; rm -rf /" not in built.replace("'a; rm -rf /'", "")
    assert built == "echo 'a; rm -rf /'"


def test_basic_style_wraps_only_segments_containing_spaces():
    assert cmdline.create_command_string(["ls", "-la"]) == "ls -la"
    assert cmdline.create_command_string(["cat", "my file"]) == 'cat "my file"'


def test_basic_is_the_default_style():
    assert cmdline.create_command_string(["cat", "my file"]) == \
        cmdline.create_command_string(["cat", "my file"], style = "basic")


def test_a_string_command_passes_through_unchanged():
    assert cmdline.create_command_string("already a string") == "already a string"
    assert cmdline.create_command_string("already a string", style = "posix") == "already a string"


@pytest.mark.parametrize("empty", [None, "", []])
def test_empty_commands_produce_an_empty_string(empty):
    assert cmdline.create_command_string(empty) == ""


###########################################################
# Command list construction
###########################################################

def test_enclosed_style_preserves_spaces_inside_quotes():
    assert cmdline.create_command_list('cat "my file"') == ["cat", '"my file"']
    assert cmdline.create_command_list('echo "a b" c') == ["echo", '"a b"', "c"]


def test_enclosed_style_splits_unquoted_commands():
    assert cmdline.create_command_list("ls -la") == ["ls", "-la"]


def test_enclosed_style_leaves_backslashes_alone():

    # Windows paths must not be treated as escape sequences.
    assert cmdline.create_command_list(r"C:\tools\app.exe -x") == [r"C:\tools\app.exe", "-x"]


def test_enclosed_style_degrades_on_unbalanced_quotes():

    # This sits in the path of every command execution, so a malformed string
    # falls back to a plain split rather than raising and killing the run.
    assert cmdline.create_command_list('echo "unterminated') == ["echo", '"unterminated']


def test_split_style_ignores_quoting():
    assert cmdline.create_command_list('cat "my file"', style = "split") == \
        ["cat", '"my', 'file"']


def test_a_list_command_is_copied_not_aliased():
    original = ["ls", "-la"]
    built = cmdline.create_command_list(original)

    assert built == original
    built.append("mutated")
    assert original == ["ls", "-la"], "the caller's list must not be mutated"


@pytest.mark.parametrize("empty", [None, "", []])
def test_empty_commands_produce_an_empty_list(empty):
    assert cmdline.create_command_list(empty) == []


###########################################################
# Output decoding
###########################################################

def test_output_is_decoded_to_text():
    assert cmdline.clean_command_output(b"plain output") == "plain output"


def test_undecodable_bytes_are_ignored_rather_than_raising():

    # Command output is arbitrary bytes; a decode error here would take down a
    # provision run over a stray byte in a log line.
    assert cmdline.clean_command_output(b"ok\xff\xfetail") == "oktail"


def test_text_output_passes_through():
    assert cmdline.clean_command_output("already text") == "already text"


###########################################################
# Secret masking
###########################################################

@pytest.mark.parametrize("flag", cmdline.SENSITIVE_FLAGS)
def test_flag_values_are_masked_in_a_list(flag):
    masked = cmdline.mask_sensitive_args(["tool", flag, "hunter2", "--other"])

    assert "hunter2" not in masked
    assert masked == ["tool", flag, "****", "--other"]


@pytest.mark.parametrize("flag", cmdline.SENSITIVE_FLAGS)
def test_flag_values_are_masked_in_a_string(flag):
    masked = cmdline.mask_sensitive_args(f"tool {flag} hunter2 --other")

    assert "hunter2" not in masked
    assert f"{flag} ****" in masked


def test_masking_leaves_ordinary_arguments_alone():
    original = ["docker", "compose", "up", "-d"]
    assert cmdline.mask_sensitive_args(original) == original


def test_a_trailing_sensitive_flag_does_not_crash():
    assert cmdline.mask_sensitive_args(["tool", "--password"]) == ["tool", "--password"]


@pytest.mark.parametrize("flag", cmdline.SENSITIVE_FLAGS)
def test_joined_flag_values_are_masked_in_a_list(flag):

    # --password=hunter2 used to pass straight through: the list branch only
    # compared whole arguments against SENSITIVE_FLAGS.
    masked = cmdline.mask_sensitive_args(["tool", f"{flag}=hunter2", "--other"])

    assert "hunter2" not in " ".join(masked)
    assert masked == ["tool", f"{flag}=****", "--other"]


@pytest.mark.parametrize("flag", cmdline.SENSITIVE_FLAGS)
def test_joined_flag_values_are_masked_in_a_string(flag):
    masked = cmdline.mask_sensitive_args(f"tool {flag}=hunter2 --other")

    assert "hunter2" not in masked
    assert f"{flag}=****" in masked


def test_several_secrets_in_one_command_are_all_masked():
    masked = cmdline.mask_sensitive_args("tool --token=abc --secret def --password=ghi")

    for secret in ["abc", "def", "ghi"]:
        assert secret not in masked


def test_a_flag_prefix_is_not_masked_by_accident():

    # --password-file names a path, not a secret, and masking it would hide
    # useful detail from the log for no gain.
    masked = cmdline.mask_sensitive_args(["tool", "--password-file", "/etc/creds"])
    assert masked == ["tool", "--password-file", "/etc/creds"]
