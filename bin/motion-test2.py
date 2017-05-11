#!/usr/bin/env python3
from picamera.array import PiMotionAnalysis
from picamera import PiCamera
import numpy as np
import logging
import os
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

camera = PiCamera()
camera.resolution = (1280, 720)
camera.framerate = 24

class MotionDetector(PiMotionAnalysis):
    def motion_detected(self):
        print('Motion detected')
        logger.info('Motion detected')

    def analyse(self, a):
        # Calculate the magnitude of all vectors with pythagoras' theorem
        a = np.sqrt(
            np.square(a['x'].astype(np.float)) +
            np.square(a['y'].astype(np.float))
        ).clip(0, 255).astype(np.uint8)
        # Count the number of vectors with a magnitude greater than our
        # threshold
        vector_count = (a > 60).sum()
        if vector_count > 10:
            self.motion_detected()

motion_detector = MotionDetector(camera)

try:
    while True:
        if not camera.recording:
            print('Starting detection')
            camera.start_recording(os.devnull, format='h264', motion_output=motion_detector)
        if camera.recording:
            print('wait_recording')
            camera.wait_recording(1)
finally:
    camera.stop_recording()
