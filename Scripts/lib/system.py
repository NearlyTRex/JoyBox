# Imports
import sys
import time

# Local imports
import logger

###########################################################
# Program control
###########################################################

# Quit program
def QuitProgram(exit_code = -1):
    sys.exit(exit_code)

# Sleep program
def SleepProgram(seconds):
    time.sleep(seconds)

# Run main function
def RunMain(main_func):
    try:
        success = main_func()
        if success is not None:
            if success:
                logger.log_info("Script completed successfully")
            else:
                logger.log_error("Script completed with errors")
                sys.exit(1)
    except KeyboardInterrupt:
        logger.log_warning("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.log_error(f"Script failed with exception: {e}")
        sys.exit(1)
