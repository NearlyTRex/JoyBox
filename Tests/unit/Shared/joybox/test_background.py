# Imports
import threading

# Third-party imports
import pytest

# Local imports
from joybox import background, config


###########################################################
# Background jobs
###########################################################

def test_a_job_needs_something_to_run():
    with pytest.raises(AssertionError, match = "job_func"):
        background.BackgroundJob(job_func = None, units_exact = 1)


@pytest.mark.parametrize("units_type", [config.UnitType.SECONDS, config.UnitType.MINUTES, config.UnitType.HOURS])
def test_an_exact_interval_is_scheduled_in_its_units(units_type):
    job = background.BackgroundJob(job_func = lambda: None, units_exact = 2, units_type = units_type)

    job.start()
    job.stop()

    assert job.job.interval == 2
    assert job.job.unit == units_type.val().lower()


def test_a_range_interval_is_scheduled():
    job = background.BackgroundJob(job_func = lambda: None, units_range = (1, 3))

    job.start()
    job.stop()

    assert (job.job.interval, job.job.latest) == (1, 3)


@pytest.mark.parametrize("units_range", [(1,), (1, 2, 3), "13"])
def test_a_malformed_range_schedules_nothing(units_range):
    job = background.BackgroundJob(job_func = lambda: None, units_range = units_range)

    job.start()
    job.stop()

    assert job.job is None


def test_stopping_waits_for_a_run_in_progress():
    # A run that is still writing when stop returns would race the caller
    # checking for what it wrote.
    started = threading.Event()
    release = threading.Event()
    finished = []

    def run_once():
        started.set()
        release.wait(5)
        finished.append(True)

    job = background.BackgroundJob(job_func = run_once, units_exact = 1)
    job.start()
    job.job.next_run = job.job.next_run.replace(year = 2000)
    assert started.wait(5)

    stopper = threading.Thread(target = job.stop)
    stopper.start()
    stopper.join(0.2)
    assert stopper.is_alive()

    release.set()
    stopper.join(5)
    assert finished == [True]
    assert not job.thread.is_alive()


def test_stopping_a_job_that_never_started_is_harmless():
    background.BackgroundJob(job_func = lambda: None, units_exact = 1).stop()


def test_an_unknown_unit_leaves_the_job_unscheduled():
    job = background.BackgroundJob(job_func = lambda: None, units_exact = 1, units_type = "Days")

    job.start()
    job.stop()

    assert job.job.job_func is None


def test_the_scheduler_thread_sleeps_between_checks(monkeypatch):
    job = background.BackgroundJob(job_func = lambda: None, units_exact = 1, sleep_interval = 3)
    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        job.should_stop.set()

    monkeypatch.setattr(background.runtime, "sleep_program", fake_sleep)
    job.start()
    job.thread.join(5)

    assert sleeps == [3]
