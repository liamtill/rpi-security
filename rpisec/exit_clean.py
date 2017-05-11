# -*- coding: utf-8 -*-

import sys
import os
import logging
from threading import current_thread

logger = logging.getLogger()


def exit_cleanup():
    #GPIO.cleanup()
    if 'camera' in vars():
        camera.stop_recording()
        camera.close()


def exit_clean(signal=None, frame=None):
    logger.info("rpi-security stopping...")
    exit_cleanup()
    sys.exit(0)


def exit_error(message):
    logger.critical(message)
    exit_cleanup()
    try:
        current_thread().getName()
    except NameError:
        sys.exit(1)
    else:
        os._exit(1)


def exception_handler(type, value, tb):
    logger.exception("Uncaught exception: {0}".format(repr(value)))
