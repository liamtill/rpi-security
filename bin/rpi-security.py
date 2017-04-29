#!/usr/bin/env python3

import os
import argparse
import logging
import logging.handlers
import RPi.GPIO as GPIO
from datetime import datetime, timedelta
import sys
import time
import signal


# Remove later
sys.path.insert(0, ".")

import rpisec


# Now begin importing slow modules and setting up camera, Telegram and threads
import picamera


from telegram import Bot
from threading import Thread, current_thread
from queue import Queue
from PIL import Image

GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

def parse_arguments():
    p = argparse.ArgumentParser(description='A simple security system to run on a Raspberry Pi.')
    p.add_argument('-c', '--config_file', help='Path to config file.', default='/etc/rpi-security.conf')
    p.add_argument('-s', '--state_file', help='Path to state file.', default='/var/lib/rpi-security/state.yaml')
    p.add_argument('-d', '--debug', help='To enable debug output to stdout', action='store_true', default=False)
    return p.parse_args()

def setup_logging(debug_mode=False, log_to_stdout=False):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    syslog_handler = logging.handlers.SysLogHandler(address = '/dev/log')
    syslog_format = logging.Formatter("%(filename)s:%(threadName)s %(message)s", "%Y-%m-%d %H:%M:%S")
    syslog_handler.setFormatter(syslog_format)
    if log_to_stdout:
        stdout_level = logging.DEBUG
        stdout_format = logging.Formatter("%(asctime)s %(levelname)-7s %(filename)s:%(lineno)-8s %(threadName)-19s %(message)s", "%Y-%m-%d %H:%M:%S")
    else:
        stdout_level = logging.CRITICAL
        stdout_format = logging.Formatter("ERROR: %(message)s")
    if debug_mode:
        syslog_handler.setLevel(logging.DEBUG)
    else:
        syslog_handler.setLevel(logging.INFO)
    logger.addHandler(syslog_handler)
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(stdout_format)
    stdout_handler.setLevel(stdout_level)
    logger.addHandler(stdout_handler)
    return logger


if __name__ == "__main__":
    args = parse_arguments()

    logger = setup_logging(debug_mode=True, log_to_stdout=args.debug)

    logger.info("rpi-security starting...")

    try:
        rpis = rpisec.rpi_security.RpiSecurity(args.config_file, args.state_file)
    except Exception as e:
        exit_error('Configuration error: {0}'.format(repr(e)))

    sys.excepthook = rpisec.exception_handler
    camera_queue = Queue()

    try:
        camera = picamera.PiCamera()
        camera.resolution = rpis.camera_image_size
        camera.vflip = rpis.camera_vflip
        camera.hflip = rpis.camera_hflip
        camera.led = False
    except Exception as e:
        exit_error('Camera module failed to intialise with error %s' % e)

    try:
        bot = Bot(token=rpis.telegram_bot_token)
    except Exception as e:
        exit_error('Failed to connect to Telegram with error: %s' % e)

    # Start the threads
    telegram_bot_thread = Thread(name='telegram_bot', target=rpisec.threads.telegram_bot, args=(rpis,))
    telegram_bot_thread.daemon = True
    telegram_bot_thread.start()
    monitor_alarm_state_thread = Thread(name='monitor_alarm_state', target=rpisec.threads.monitor_alarm_state, args=(rpis,))
    monitor_alarm_state_thread.daemon = True
    monitor_alarm_state_thread.start()
    capture_packets_thread = Thread(name='capture_packets', target=rpisec.threads.capture_packets, args=(rpis,))
    capture_packets_thread.daemon = True
    capture_packets_thread.start()
    # process_photos_thread = Thread(name='process_photos', target=process_photos, args=(rpis,))
    # process_photos_thread.daemon = True
    # process_photos_thread.start()
    signal.signal(signal.SIGTERM, rpisec.exit_clean)
    try:
        # GPIO.setup(rpis.pir_pin, GPIO.IN)
        # GPIO.add_event_detect(rpis.pir_pin, GPIO.RISING, callback=motion_detected)
        logger.info("rpi-security running")
        # telegram_send_message('rpi-security running')
        while True:
            time.sleep(100)
    except KeyboardInterrupt:
        rpisec.exit_clean()
