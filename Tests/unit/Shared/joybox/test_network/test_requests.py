# Imports
import pytest

# Local imports
from joybox import network
from network_helpers import FakeResponse, only_call


###########################################################
# Remote requests
#
# Every request goes out through requests, and every one of these returns
# nothing rather than raising when the far end misbehaves - callers treat a
# None as "not available" and carry on.
###########################################################

###########################################################
# Reachability
###########################################################

def test_a_serving_url_is_reachable(requests_module):
    assert network.is_url_reachable("https://example.test") is True


@pytest.mark.parametrize("status_code", [301, 404, 500])
def test_a_url_that_does_not_answer_with_success_is_unreachable(requests_module, status_code):
    requests_module["response"] = FakeResponse(status_code = status_code)

    assert network.is_url_reachable("https://example.test") is False


def test_a_refused_connection_is_unreachable(requests_module):
    requests_module["error"] = OSError("connection refused")

    assert network.is_url_reachable("https://example.test") is False


###########################################################
# JSON
###########################################################

def test_json_is_returned_from_a_successful_response(requests_module):
    requests_module["response"] = FakeResponse(payload = {"models": []})

    assert network.get_remote_json("https://example.test/api") == {"models": []}


def test_a_json_request_asks_for_json(requests_module):
    network.get_remote_json("https://example.test/api")

    assert only_call(requests_module)["headers"] == {"Accept": "application/json"}


def test_a_json_request_can_carry_its_own_headers(requests_module):
    network.get_remote_json("https://example.test/api", headers = {"HX-Request": "true"})

    assert only_call(requests_module)["headers"] == {"HX-Request": "true"}


@pytest.mark.parametrize("status_code", [404, 500])
def test_an_unsuccessful_json_response_yields_nothing(requests_module, status_code):
    requests_module["response"] = FakeResponse(status_code = status_code, payload = {"error": "nope"})

    assert network.get_remote_json("https://example.test/api") is None


def test_an_unreachable_json_endpoint_yields_nothing(requests_module):
    requests_module["error"] = OSError("no route to host")

    assert network.get_remote_json("https://example.test/api") is None


def test_a_response_that_is_not_json_yields_nothing(requests_module):
    requests_module["response"] = FakeResponse(payload = ValueError("not json"))

    assert network.get_remote_json("https://example.test/api") is None


def test_a_failed_json_request_can_quit_the_program(requests_module):
    requests_module["error"] = OSError("no route to host")

    with pytest.raises(SystemExit):
        network.get_remote_json("https://example.test/api", exit_on_failure = True)


def test_json_is_posted_as_the_request_body(requests_module):
    requests_module["response"] = FakeResponse(payload = {"ok": True})

    result = network.post_remote_json("https://example.test/api", data = {"prompt": "hello"})

    assert result == {"ok": True}
    assert only_call(requests_module)["json"] == {"prompt": "hello"}


def test_a_post_uses_the_post_method(requests_module):
    network.post_remote_json("https://example.test/api", data = {})

    assert only_call(requests_module)["method"] == "post"


def test_an_unsuccessful_post_yields_nothing(requests_module):
    requests_module["response"] = FakeResponse(status_code = 401, payload = {"error": "denied"})

    assert network.post_remote_json("https://example.test/api", data = {}) is None


def test_a_failed_post_can_quit_the_program(requests_module):
    requests_module["error"] = OSError("no route to host")

    with pytest.raises(SystemExit):
        network.post_remote_json("https://example.test/api", exit_on_failure = True)


###########################################################
# HTML
###########################################################

def test_html_is_returned_as_text(requests_module):
    requests_module["response"] = FakeResponse(text = "<html></html>")

    assert network.get_remote_html("https://example.test") == "<html></html>"


def test_a_json_request_does_not_wait_forever(requests_module):
    network.get_remote_json("https://example.test/api")

    assert only_call(requests_module)["timeout"] == 10


def test_an_html_request_does_not_wait_forever(requests_module):
    # A scrape that hangs holds up the whole run with no way to interrupt it.
    network.get_remote_html("https://example.test")

    assert only_call(requests_module)["timeout"] == 10


def test_an_html_request_sends_no_headers_of_its_own(requests_module):
    network.get_remote_html("https://example.test")

    assert only_call(requests_module)["headers"] == {}


def test_an_unsuccessful_html_response_yields_nothing(requests_module):
    requests_module["response"] = FakeResponse(status_code = 404, text = "not found")

    assert network.get_remote_html("https://example.test") is None


def test_an_unreachable_page_yields_nothing(requests_module):
    requests_module["error"] = OSError("no route to host")

    assert network.get_remote_html("https://example.test") is None


###########################################################
# XML
###########################################################

def test_xml_is_parsed_into_a_mapping(requests_module):
    requests_module["response"] = FakeResponse(text = "<root><name>value</name></root>")

    assert network.get_remote_xml("https://example.test/feed") == {"root": {"name": "value"}}


def test_an_xml_request_asks_for_xml(requests_module):
    requests_module["response"] = FakeResponse(text = "<root/>")

    network.get_remote_xml("https://example.test/feed")

    assert only_call(requests_module)["headers"] == {"Accept": "text/xml"}


def test_malformed_xml_yields_nothing(requests_module):
    requests_module["response"] = FakeResponse(text = "<root><unclosed>")

    assert network.get_remote_xml("https://example.test/feed") is None


def test_an_unsuccessful_xml_response_yields_nothing(requests_module):
    requests_module["response"] = FakeResponse(status_code = 500, text = "<root/>")

    assert network.get_remote_xml("https://example.test/feed") is None


def test_a_reachability_check_does_not_wait_forever(requests_module):
    network.is_url_reachable("https://example.test")

    assert only_call(requests_module)["timeout"] == 10


def test_an_html_request_can_carry_its_own_headers(requests_module):
    network.get_remote_html("https://example.test", headers = {"User-Agent": "JoyBox"})

    assert only_call(requests_module)["headers"] == {"User-Agent": "JoyBox"}


def test_a_failed_html_request_can_quit_the_program(requests_module):
    requests_module["error"] = OSError("no route to host")

    with pytest.raises(SystemExit):
        network.get_remote_html("https://example.test", exit_on_failure = True)


def test_an_xml_request_can_carry_its_own_headers(requests_module):
    requests_module["response"] = FakeResponse(text = "<root/>")

    network.get_remote_xml("https://example.test/feed", headers = {"Accept": "application/rss+xml"})

    assert only_call(requests_module)["headers"] == {"Accept": "application/rss+xml"}


def test_an_xml_request_does_not_wait_forever(requests_module):
    requests_module["response"] = FakeResponse(text = "<root/>")

    network.get_remote_xml("https://example.test/feed")

    assert only_call(requests_module)["timeout"] == 10


def test_a_failed_xml_request_can_quit_the_program(requests_module):
    requests_module["error"] = OSError("no route to host")

    with pytest.raises(SystemExit):
        network.get_remote_xml("https://example.test/feed", exit_on_failure = True)


###########################################################
# Posting
###########################################################

def test_a_post_asks_for_json_by_default(requests_module):
    network.post_remote_json("https://example.test/api", data = {})

    assert only_call(requests_module)["headers"] == {"Accept": "application/json"}


def test_a_post_can_carry_its_own_headers(requests_module):
    network.post_remote_json("https://example.test/api", headers = {"Authorization": "Bearer x"})

    assert only_call(requests_module)["headers"] == {"Authorization": "Bearer x"}


def test_a_post_does_not_wait_forever(requests_module):
    network.post_remote_json("https://example.test/api", data = {})

    assert only_call(requests_module)["timeout"] == 10


def test_a_pretend_post_sends_nothing(requests_module):
    # A POST changes state at the far end, which a pretend run must not do.
    assert network.post_remote_json("https://example.test/api", data = {}, pretend_run = True) is None
    assert requests_module["calls"] == []


###########################################################
# Verbose logging
###########################################################

@pytest.mark.parametrize("call", [
    lambda: network.get_remote_json("https://example.test/api", verbose = True),
    lambda: network.get_remote_html("https://example.test", verbose = True),
    lambda: network.post_remote_json("https://example.test/api", verbose = True),
    lambda: network.get_remote_xml("https://example.test/feed", verbose = True),
])
def test_a_verbose_request_logs_the_url_and_status(requests_module, monkeypatch, call):
    logged = []
    monkeypatch.setattr(network.logger, "log_info", logged.append)
    requests_module["response"] = FakeResponse(text = "<root/>", payload = {})

    call()

    assert any("example.test" in line for line in logged)
    assert any("200" in line for line in logged)


def test_an_unreachable_post_endpoint_yields_nothing(requests_module):
    requests_module["error"] = OSError("no route to host")

    assert network.post_remote_json("https://example.test/api", data = {}) is None
