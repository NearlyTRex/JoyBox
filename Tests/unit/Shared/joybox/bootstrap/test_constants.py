# Imports
import argparse

# Third-party imports
import pytest

# Local imports
import joybox.bootstrap.constants as constants


@pytest.mark.parametrize("environment", list(constants.EnvironmentType), ids = str)
def test_the_printed_name_is_the_value(environment):
    # --type lists choices by str() and parses them back by value.
    assert str(environment) == environment.value
    assert constants.EnvironmentType(str(environment)) is environment


@pytest.mark.parametrize("environment", list(constants.EnvironmentType), ids = str)
def test_an_option_typed_by_the_enum_parses_each_choice(environment):
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", type = constants.EnvironmentType, choices = list(constants.EnvironmentType))

    assert parser.parse_args(["-t", str(environment)]).t is environment


def test_an_unknown_environment_is_rejected():
    with pytest.raises(ValueError, match = "local_macos"):
        constants.EnvironmentType("local_macos")
