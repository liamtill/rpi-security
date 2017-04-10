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

import rpisecurity


# Now begin importing slow modules and setting up camera, Telegram and threads
import picamera
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import srp, Ether, ARP
from scapy.all import conf as scapy_conf
scapy_conf.promisc=0
scapy_conf.sniff_promisc=0

import telegram
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, RegexHandler
from threading import Thread, current_thread
from PIL import Image

GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

def parse_arguments():
    p = argparse.ArgumentParser(description='A simple security system to run on a Raspberry Pi.')
    p.add_argument('-c', '--config_file', help='Path to config file.', default='/etc/rpi-security.conf')
    p.add_argument('-s', '--state_file', help='Path to state file.', default='/var/lib/rpi-security/state.yaml')
    p.add_argument('-d', '--debug', help='To enable debug output to stdout', action='store_true', default=False)
    return p.parse_args()


def exit_cleanup():
    GPIO.cleanup()
    if 'camera' in vars():
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
    logger.exception("Uncaught exception: {0}" % format(str(value)))


def setup_logging(debug_mode=False, log_to_stdout=False):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    syslog_handler = logging.handlers.SysLogHandler(address = '/dev/log')
    syslog_format = logging.Formatter("%(filename)s:%(threadName)s %(message)s", "%Y-%m-%d %H:%M:%S")
    syslog_handler.setFormatter(syslog_format)
    if log_to_stdout:
        stdout_level = logging.DEBUG
        stdout_format = logging.Formatter("%(asctime)s %(levelname)-7s %(filename)s:%(lineno)-3s %(threadName)-19s %(message)s", "%Y-%m-%d %H:%M:%S")
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

    alarm_state = rpisecurity.RpiAlarmState()

    try:
        config = rpisecurity.RpiConfig(args.config_file, args.state_file)
    except Exception as e:
        exit_error('Configuration error: {0}'.format(repr(e)))



    sys.excepthook = exception_handler
    captured_from_camera = []

    try:
        camera = picamera.PiCamera()
        camera.resolution = config.camera_image_size
        camera.vflip = config.camera_vflip
        camera.hflip = config.camera_hflip
        camera.led = False
    except Exception as e:
        exit_error('Camera module failed to intialise with error %s' % e)
    try:
        bot = telegram.Bot(token=config.telegram_bot_token)
    except Exception as e:
        exit_error('Failed to connect to Telegram with error: %s' % e)

    # Start the threads
    telegram_bot_thread = Thread(name='telegram_bot', target=telegram_bot,
        kwargs={
            'token': config.telegram_bot_token,
            'camera_save_path': config.camera_save_path,
            'camera_capture_length': config.camera_capture_length,
            'camera_mode': config.camera_mode
            }
        )
    telegram_bot_thread.daemon = True
    telegram_bot_thread.start()
    monitor_alarm_state_thread = Thread(name='monitor_alarm_state', target=monitor_alarm_state,
        kwargs={
            'packet_timeout': config.packet_timeout,
            'network_address': config.network_address,
            'mac_addresses': config.mac_addresses
        })
    monitor_alarm_state_thread.daemon = True
    monitor_alarm_state_thread.start()
    capture_packets_thread = Thread(name='capture_packets', target=capture_packets,
        kwargs={
            'network_interface': config.network_interface,
            'network_interface_mac': config.network_interface_mac,
            'mac_addresses': config.mac_addresses
        })
    capture_packets_thread.daemon = True
    capture_packets_thread.start()
    process_photos_thread = Thread(name='process_photos', target=process_photos,
        kwargs={
            'network_address': config.network_address,
            'mac_addresses': config.mac_addresses
        })
    process_photos_thread.daemon = True
    process_photos_thread.start()
    signal.signal(signal.SIGTERM, exit_clean)
    time.sleep(2)
    try:
        GPIO.setup(config.pir_pin, GPIO.IN)
        GPIO.add_event_detect(config.pir_pin, GPIO.RISING, callback=motion_detected)
        logger.info("rpi-security running")
        telegram_send_message('rpi-security running')
        while 1:
            time.sleep(100)
    except KeyboardInterrupt:
        exit_clean()
