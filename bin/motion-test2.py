#!/usr/bin/env python3
from picamera.array import PiMotionAnalysis
from picamera import PiCamera
import numpy as np
import logging
import os
import random
import sys
import time
from threading import Lock, Thread
from queue import Queue


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
stdout_level = logging.DEBUG
stdout_format = logging.Formatter("%(asctime)s %(levelname)-7s %(filename)s:%(lineno)-12s %(threadName)-23s %(message)s", "%Y-%m-%d %H:%M:%S")
stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(stdout_format)
stdout_handler.setLevel(stdout_level)
logger.addHandler(stdout_handler)


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()


class RpisCamera(object):
    def __init__(self):
        self.lock = Lock()
        self.queue = Queue()
        self.motion_magnitude = 60
        self.motion_vectors = 10
        self.motion_framerate = 24

        try:
            self.camera = PiCamera()
            self.camera.resolution = (2592, 1944)
            self.camera.vflip = False
            self.camera.hflip = False
            self.camera.led = True
        except Exception as e:
            logger.error('Camera module failed to intialise with error %s' % e)
            sys.exit(1)

        self.motion_detector = MotionDetector(self.camera)

    def take_photo(self, output_file):
        try:
            with self.lock:
                logger.info("Lock got")
                time.sleep(1)
                self.camera.resolution = (2592, 1944)
                self.camera.capture(output_file, use_video_port=False)
        except Exception as e:
            logger.error('Failed to take photo: %s' % e)
            return False
        else:
            logger.info("Captured image: %s" % output_file)
            return True

    def start_motion_detection(self):
        logger.info("Starting motion detection")
        while True:
            time.sleep(0.1)
            while not self.lock.locked() and state is 'armed':
                if self.camera.recording:
                    #logger.info('checking recording')
                    self.camera.wait_recording(0.1)
                else:
                    self.camera.resolution = (1280, 720)
                    self.camera.framerate = 24
                    self.camera.start_recording(os.devnull, format='h264', motion_output=self.motion_detector)
                    logger.debug("STARTED motion detection")
            else:
                if self.camera.recording:
                    self.camera.stop_recording()
                    logger.info('STOPPED motion detection')

    def stop_motion_detection(self):
        if not self.camera.recording:
            return
        try:
            self.camera.stop_recording()
        except AttributeError:
            pass
        if not self.camera.recording:
            self.lock.release()
            logger.debug("Stopped motion detection")
        else:
            logger.error("Stop of motion detection failed")


class MotionDetector(PiMotionAnalysis):
    def motion_detected(self):
        logger.info('Motion detected')

    def analyse(self, a):
        a = np.sqrt(
            np.square(a['x'].astype(np.float)) +
            np.square(a['y'].astype(np.float))
        ).clip(0, 255).astype(np.uint8)
        vector_count = (a > 60).sum()
        if vector_count > 10:
            self.motion_detected()


class MotionDetector(PiMotionAnalysis):
    def motion_detected(self):
        logger.info('Motion detected')

    def analyse(self, a):
        a = np.sqrt(
            np.square(a['x'].astype(np.float)) +
            np.square(a['y'].astype(np.float))
        ).clip(0, 255).astype(np.uint8)
        vector_count = (a > 60).sum()
        if vector_count > 20:
            self.motion_detected()


def telegram_bot(my_camera):
    logger.info("thread running")
    global state
    while True:
        time.sleep(random.randint(5, 8))
        my_camera.take_photo('taken_from_telegram_bot.jpeg')

def monitor_alarm_state(my_camera):
    logger.info("thread running")
    global state
    while True:
        time.sleep(0.1)
        if state is 'armed':
            my_camera.start_motion_detection()

def change_alarm_state():
    logger.info("thread running")
    global state
    while True:
        time.sleep(random.randint(5, 8))
        state = random.choice(['armed', 'disarmed'])
        logger.info("new state: {0}".format(state))

my_camera = RpisCamera()

state = 'armed'

telegram_bot_thread = Thread(name='telegram_bot', target=telegram_bot, args=(my_camera,))
telegram_bot_thread.daemon = True
telegram_bot_thread.start()

monitor_alarm_state_thread = Thread(name='monitor_alarm_state', target=monitor_alarm_state, args=(my_camera,))
monitor_alarm_state_thread.daemon = True
monitor_alarm_state_thread.start()

monitor_alarm_state_thread = Thread(name='change_alarm_state', target=change_alarm_state)
monitor_alarm_state_thread.daemon = True
monitor_alarm_state_thread.start()

if __name__ == "__main__":
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        sys.exit(0)
