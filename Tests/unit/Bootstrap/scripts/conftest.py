# Third-party imports
import pytest


# A sandbox with the deploy account the init scripts are run for
@pytest.fixture
def server(shell_sandbox):
    shell_sandbox.add_user("deploy")
    return shell_sandbox
