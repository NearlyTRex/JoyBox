# Imports
import importlib
import threading

# Local imports
from joybox import config
from joybox import validation
from joybox import runtime

# Get schedule, imported on first use
def _get_schedule():
    return importlib.import_module("schedule")

# Background job
class BackgroundJob:

    # Constructor
    def __init__(self,
        job_func,
        units_exact = None,
        units_range = None,
        units_type = config.UnitType.SECONDS,
        sleep_interval = 0):

        # Check params
        validation.assert_callable(job_func, "job_func")

        # Save params
        self.job = None
        self.job_scheduler = None
        self.job_func = job_func
        self.units_exact = units_exact
        self.units_range = units_range
        self.units_type = units_type
        self.sleep_interval = sleep_interval
        self.should_stop = threading.Event()
        self.thread = None

    # Run the scheduler until stopped
    def _run_scheduler(self):
        while not self.should_stop.is_set():
            self.job_scheduler.run_pending()
            if isinstance(self.sleep_interval, int) and self.sleep_interval > 0:
                runtime.sleep_program(self.sleep_interval)

    # Create the job every exact number of units, or every range of them
    def _create_job(self):
        if isinstance(self.units_exact, int):
            self.job = self.job_scheduler.every(self.units_exact)
        elif isinstance(self.units_range, (tuple, list)):
            if len(self.units_range) == 2:
                self.job = self.job_scheduler.every(self.units_range[0]).to(self.units_range[1])

    # Schedule the job function in the job's unit of seconds, minutes or hours
    def _configure_job(self):
        if not self.job:
            return
        if self.units_type == config.UnitType.SECONDS:
            self.job.seconds.do(self.job_func)
        elif self.units_type == config.UnitType.MINUTES:
            self.job.minutes.do(self.job_func)
        elif self.units_type == config.UnitType.HOURS:
            self.job.hours.do(self.job_func)

    # Start the job
    def start(self):

        # Create scheduler
        schedule = _get_schedule()
        self.job_scheduler = schedule.Scheduler()

        # Create job
        self._create_job()

        # Configure job
        self._configure_job()

        # Start thread
        self.thread = threading.Thread(target = self._run_scheduler)
        self.thread.start()

    # Stop the job, waiting for a run in progress to finish
    def stop(self):
        self.should_stop.set()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join()
