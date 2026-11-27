# Imports
import pytest

# Local imports
from joybox import dispatch


###########################################################
# Calling a handler with the options it names
###########################################################

def test_a_handler_is_given_only_the_options_it_names():
    def handler(model_name = None, show_all = False):
        return (model_name, show_all)

    assert dispatch.call_with_options(handler, model_name = "m", purpose = "p", show_all = True) == ("m", True)


def test_a_handler_that_names_no_options_is_called_without_any():
    def handler():
        return "ran"

    assert dispatch.call_with_options(handler, model_name = "m", show_all = True) == "ran"


def test_positional_arguments_are_passed_through():
    def handler(game_info, verbose = False):
        return (game_info, verbose)

    assert dispatch.call_with_options(handler, "game", verbose = True, pretend_run = True) == ("game", True)


def test_a_handler_taking_any_keyword_is_given_every_option():
    def handler(**kwargs):
        return kwargs

    assert dispatch.call_with_options(handler, model_name = "m", show_all = True) == {"model_name": "m", "show_all": True}


def test_an_option_the_handler_needs_but_nobody_offers_is_still_an_error():
    def handler(model_name):
        return model_name

    with pytest.raises(TypeError, match = "model_name"):
        dispatch.call_with_options(handler, show_all = True)
