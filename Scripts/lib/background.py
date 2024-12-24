# Imports
import os, os.path
import sys
import threading

# Local imports
import config
import system

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
        system.AssertCallable(job_func, "job_func")

        # Save params
        self.job = None
        self.job_scheduler = None
        self.job_func = job_func
        self.units_exact = units_exact
        self.units_range = units_range
        self.units_type = units_type
        self.sleep_interval = sleep_interval
        self.should_stop = threading.Event()

    # Start the job
    def start(self):

        # Thread for running scheduler
        class ScheduleThread(threading.Thread):
            @classmethod
            def run(cls):
                while not self.should_stop.is_set():
                    self.job_scheduler.run_pending()
                    if isinstance(self.sleep_interval, int) and self.sleep_interval > 0:
                        system.SleepProgram(self.sleep_interval)

        # Create scheduler
        import schedule
        self.job_scheduler = schedule.Scheduler()

        # Create job
        if isinstance(self.units_exact, int):
            self.job = self.job_scheduler.every(self.units_exact)
        elif isinstance(self.units_range, tuple) or isinstance(self.units_range, list):
            if len(self.units_range) == 2:
                self.job = self.job_scheduler.every(self.units_range[0]).to(self.units_range[1])

        # Configure job
        if self.job:
            if self.units_type == config.UnitType.SECONDS:
                self.job.seconds.do(self.job_func)
            elif self.units_type == config.UnitType.MINUTES:
                self.job.minutes.do(self.job_func)
            elif self.units_type == config.UnitType.HOURS:
                self.job.hours.do(self.job_func)

        # Start thread
        continuous_thread = ScheduleThread()
        continuous_thread.start()

    # Stop the job
    def stop(self):
        self.should_stop.set()
