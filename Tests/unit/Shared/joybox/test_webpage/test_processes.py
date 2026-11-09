# Imports
import signal
import types

# Third-party imports
import pytest

# Local imports
from joybox import webpage
from webpage_helpers import FakeDriver

# The real pause, before the suite's fixture records pauses in its place
REAL_PAUSE = webpage.pause

###########################################################
# Page load pacing
#
# Loads from one site are spaced by page_load_interval_seconds, so a long
# scrape asks a site for one page at a time at a steady pace.
###########################################################

@pytest.fixture
def clock(monkeypatch):
    state = {"now": 100.0}
    monkeypatch.setattr(webpage.time, "monotonic", lambda: state["now"])
    return state


def test_the_first_load_from_a_site_does_not_wait(clock, page_load_pauses):
    webpage.wait_for_page_load_turn("https://gamefaqs.example/search")

    assert page_load_pauses == []


def test_a_second_load_from_a_site_waits_out_the_interval(clock, page_load_pauses):
    webpage.wait_for_page_load_turn("https://gamefaqs.example/")
    clock["now"] += 1
    webpage.wait_for_page_load_turn("https://gamefaqs.example/search")

    assert page_load_pauses == [webpage.default_page_load_interval_seconds - 1]


def test_loads_from_different_sites_do_not_wait_on_each_other(clock, page_load_pauses):
    webpage.wait_for_page_load_turn("https://gamefaqs.example/")
    webpage.wait_for_page_load_turn("https://thegamesdb.example/")

    assert page_load_pauses == []


def test_a_load_after_the_interval_does_not_wait(clock, page_load_pauses):
    webpage.wait_for_page_load_turn("https://gamefaqs.example/")
    clock["now"] += webpage.default_page_load_interval_seconds
    webpage.wait_for_page_load_turn("https://gamefaqs.example/game")

    assert page_load_pauses == []


def test_loading_urls_paces_them_by_site(clock, page_load_pauses):
    driver = FakeDriver()

    assert webpage.load_url(driver, "https://gamefaqs.example/") is True
    assert webpage.load_url(driver, "https://gamefaqs.example/search") is True

    assert driver.visited == ["https://gamefaqs.example/", "https://gamefaqs.example/search"]
    assert page_load_pauses == [webpage.default_page_load_interval_seconds]


def test_a_pretend_load_is_not_paced(clock, page_load_pauses):
    webpage.load_url(FakeDriver(), "https://gamefaqs.example/", pretend_run = True)
    webpage.load_url(FakeDriver(), "https://gamefaqs.example/", pretend_run = True)

    assert page_load_pauses == []
    assert webpage.last_page_loads == {}


def test_the_pause_sleeps(monkeypatch):
    slept = []
    monkeypatch.setattr(webpage.time, "sleep", slept.append)

    REAL_PAUSE(2)

    assert slept == [2]

###########################################################
# Browser process groups
#
# A driver and the browser it launches run in a process group of their own,
# which is stopped whole: a launcher script such as brave-browser runs the
# browser as its child, and quitting the driver leaves that child running.
###########################################################

@pytest.fixture
def groups(monkeypatch, clock):
    # {group: signals until it is empty}; a group not listed is already gone
    state = {"alive": {}, "sent": []}

    def killpg(group_id, signal_number):
        state["sent"].append((group_id, signal_number))
        if state["alive"].get(group_id, 0) <= 0:
            raise ProcessLookupError(group_id)
        state["alive"][group_id] -= 1

    monkeypatch.setattr(webpage.os, "killpg", killpg, raising = False)
    monkeypatch.setattr(webpage, "running_browser_groups", set())
    monkeypatch.setattr(webpage, "pause", lambda seconds: clock.update(now = clock["now"] + seconds))
    return state


def service(pid):
    return types.SimpleNamespace(process = types.SimpleNamespace(pid = pid))


def test_drivers_start_in_a_session_of_their_own(groups):
    assert webpage.get_driver_service_options() == {"popen_kw": {"start_new_session": True}}


def test_without_process_groups_drivers_start_as_usual(monkeypatch):
    monkeypatch.delattr(webpage.os, "killpg", raising = False)

    assert webpage.get_driver_service_options() == {}
    assert webpage.get_service_group(service(5)) is None


@pytest.mark.parametrize("candidate", [None, types.SimpleNamespace(), types.SimpleNamespace(process = None)])
def test_a_service_that_never_started_has_no_group(groups, candidate):
    assert webpage.get_service_group(candidate) is None


def test_a_group_already_gone_gets_only_the_stop_signal(groups):
    webpage.running_browser_groups.add(40)

    webpage.stop_browser_group(40)

    assert groups["sent"] == [(40, signal.SIGTERM)]
    assert webpage.running_browser_groups == set()


def test_a_group_that_exits_when_asked_is_not_killed(groups):
    groups["alive"][40] = 2

    webpage.stop_browser_group(40)

    assert groups["sent"] == [(40, signal.SIGTERM), (40, 0), (40, 0)]


def test_a_group_that_outlives_the_grace_period_is_killed(groups):
    groups["alive"][40] = 10 ** 6

    webpage.stop_browser_group(40)

    assert groups["sent"][-1] == (40, signal.SIGKILL)


def test_no_group_is_nothing_to_stop(groups):
    webpage.stop_browser_group(None)

    assert groups["sent"] == []


def test_a_started_browser_is_tracked_until_destroyed(groups):
    groups["alive"][41] = 1
    driver = webpage.start_browser(lambda service, options: FakeDriver(), service(41), None)
    driver.service = service(41)
    assert webpage.running_browser_groups == {41}

    assert webpage.destroy_web_driver(driver) is True

    assert driver.quit_calls == 1
    assert webpage.running_browser_groups == set()
    assert groups["sent"][0] == (41, signal.SIGTERM)


def test_a_browser_whose_start_fails_has_its_group_stopped(groups):
    def browser(service, options):
        raise RuntimeError("session not created")

    with pytest.raises(RuntimeError):
        webpage.start_browser(browser, service(42), None)

    assert groups["sent"] == [(42, signal.SIGTERM)]
    assert webpage.running_browser_groups == set()


def test_a_browser_without_a_group_is_not_tracked(groups):
    webpage.start_browser(lambda service, options: FakeDriver(), types.SimpleNamespace(), None)

    assert webpage.running_browser_groups == set()


def test_the_group_is_stopped_even_when_quit_fails(groups):
    class Stubborn(FakeDriver):
        def quit(self):
            raise RuntimeError("already gone")
    driver = Stubborn()
    driver.service = service(43)

    assert webpage.destroy_web_driver(driver) is False
    assert groups["sent"] == [(43, signal.SIGTERM)]


def test_browsers_still_running_at_exit_are_stopped(groups):
    webpage.running_browser_groups.update({44, 45})

    webpage.stop_running_browsers()

    assert sorted(groups["sent"]) == [(44, signal.SIGTERM), (45, signal.SIGTERM)]
    assert webpage.running_browser_groups == set()
