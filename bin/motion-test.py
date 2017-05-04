import os
import picamera
import numpy as np
from picamera.array import PiMotionAnalysis
import time

MOTION_MAGNITUDE = 60
MOTION_VECTORS = 20

camera = picamera.PiCamera()
camera.framerate = 24

capturing_photo = False

def motion_detected():
    print('Detected motion!')
    capturing_photo = True
    time.sleep(1)
    camera.stop_recording()
    time.sleep(1)
    camera.resolution = (2592, 1944)
    time.sleep(1)
    camera.capture('full-size.jpeg')
    time.sleep(1)
    capturing_photo = False

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
        time.sleep(1)
        if not camera.recording and not capturing_photo:
            print('Starting detection')
            camera.resolution = (1280, 720)
            camera.start_recording(os.devnull, format='h264', motion_output=motion_detector)
        if camera.recording:
            print('wait_recording')
            camera.wait_recording(1)
finally:
    camera.stop_recording()
