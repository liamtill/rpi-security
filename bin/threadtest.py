#!/usr/bin/python

import os
import argparse
import logging
import logging.handlers
from ConfigParser import SafeConfigParser
from datetime import datetime, timedelta
import sys
import time
import signal
import yaml
import threading
import picamera
from picamera.array import PiMotionAnalysis


def motion_detection_thread():
    print 'motion_detection_thread running'
    global camera_lock
    global camera
    MOTION_MAGNITUDE = 60   # the magnitude of vectors required for motion
    MOTION_VECTORS = 10     # the number of vectors required to detect motion
    def motion_detected():
        print 'Motion detected'
    def camera_stop_recording():
        if camera.recording:
            camera.stop_recording()
    class MyMotionDetector(PiMotionAnalysis):
        def analyse(self, a):
            a = np.sqrt(
                np.square(a['x'].astype(np.float)) +
                np.square(a['y'].astype(np.float))
            ).clip(0, 255).astype(np.uint8)
            vector_count = (a > MOTION_MAGNITUDE).sum()
            if vector_count > MOTION_VECTORS:
                motion_detected()
    while True:
        while not camera_lock.locked():
            print 'monitoring...'
            time.sleep(1)
        else:
            print 'stopping monitoring'
            while camera_lock.locked():
                pass

def take_photos():
    print 'take_photos running'
    global camera_lock
    global camera
    while True:
        time.sleep(30)
        camera_lock.acquire()
        time.sleep(1)
        print 'taking photo...'
        #take_photo('temp.jpeg')
        time.sleep(3)
        print 'done'
        camera_lock.release()


if __name__ == "__main__":
    camera_lock = threading.Lock()
    camera = picamera.PiCamera()
    motion_detection_thread = threading.Thread(name='motion_detection_thread', target=motion_detection_thread)
    motion_detection_thread.daemon = True
    motion_detection_thread.start()
    take_photos = threading.Thread(name='take_photos', target=take_photos)
    take_photos.daemon = True
    take_photos.start()
    try:
        for t in threading.enumerate():
    	    if isinstance(threading.current_thread(), threading._MainThread):
    		    continue
    	    t.join()
        print 'running'
        while True:
            time.sleep(100)
    except KeyboardInterrupt:
        print 'stopping'
        sys.exit(0)