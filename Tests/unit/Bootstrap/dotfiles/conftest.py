# Imports
import os

# Third-party imports
import pytest

DOTFILES_DIR = "Bootstrap/dotfiles"


class Shell:

    def __init__(self, sandbox):
        self.sandbox = sandbox

    # Source dotfiles from the repository, as the managed block does, then run body
    def source(self, names, body = "", env = None):
        lines = ['source "%s"' % os.path.join(self.sandbox.repo_root, DOTFILES_DIR, name) for name in names]
        return self.sandbox.run_command(["bash", "-c", "\n".join(lines + [body])], env = env)


@pytest.fixture
def shell(shell_sandbox):
    return Shell(shell_sandbox)
