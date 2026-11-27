# Local imports
from joybox import logger
from joybox import runtime

###########################################################
# Program control
###########################################################

# Run main function
def run_main(main_func):
    try:
        success = main_func()
        if success is not None:
            if success:
                logger.log_info("Script completed successfully")
            else:
                logger.log_error("Script completed with errors")
                runtime.quit_program(1)
    except KeyboardInterrupt:
        logger.log_warning("\nOperation cancelled by user")
        runtime.quit_program(130)
