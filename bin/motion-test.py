#!/usr/bin/env python3

import os
import picamera
import numpy as np
from picamera.array import PiMotionAnalysis
import time

MOTION_MAGNITUDE = 60
MOTION_VECTORS = 10

camera = picamera.PiCamera()
camera.framerate = 24
camera.resolution = (1280, 720)

def motion_detected():
    print('Detected motion!')

class MyMotionDetector(PiMotionAnalysis):
    def analyse(self, a):
        a = np.sqrt(
            np.square(a['x'].astype(np.float)) +
            np.square(a['y'].astype(np.float))
            ).clip(0, 255).astype(np.uint8)
        vector_count = (a > MOTION_MAGNITUDE).sum()
        if vector_count > MOTION_VECTORS:
            motion_detected()

motion_detector = MyMotionDetector(camera)

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
