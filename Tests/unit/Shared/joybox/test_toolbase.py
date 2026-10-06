# Local imports
from joybox import toolbase


###########################################################
# Tool base defaults
#
# A tool that overrides nothing is a nameless no-op whose setup steps succeed.
###########################################################

def test_the_base_tool_has_no_name_or_config():
    tool = toolbase.ToolBase()

    assert tool.get_name() == ""
    assert tool.get_config() == {}


def test_every_base_setup_step_succeeds():
    tool = toolbase.ToolBase()

    assert tool.setup() is True
    assert tool.setup_offline() is True
    assert tool.configure() is True
