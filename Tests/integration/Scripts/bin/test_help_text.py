# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import manpage


###########################################################
# Help text
#
# The command reference in Docs is generated from each script's parser, so the
# help text is the only documentation a command has. A gap here is a gap on
# the page, and a page that differs from its script was edited by hand or not
# regenerated - run build_man_pages.
###########################################################

@pytest.fixture(scope = "module")
def specs(scripts_bin_dir, shared_dir):
    return manpage.describe_scripts(scripts_bin_dir, shared_dir)


def test_every_script_was_described(specs, script_files):
    assert sorted(specs) == sorted(name for name, _ in script_files)


def test_every_script_has_complete_help_text(specs):
    problems = [
        "%s: %s" % (tool_name, problem)
        for tool_name, spec in specs.items()
        for problem in manpage.find_help_problems(tool_name, spec, specs.keys())]

    assert not problems, "incomplete help text:\n  " + "\n  ".join(problems)


def test_the_command_reference_is_up_to_date(specs, repo_root):
    stale, extra = manpage.find_stale_pages(
        manpage.render_all(specs),
        os.path.join(repo_root, "Docs", "reference", "man"))

    assert not (stale or extra), (
        "run build_man_pages; out of date: %s; no longer generated: %s" % (stale, extra))
