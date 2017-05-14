# -*- coding: utf-8 -*-

import logging
import os
import time
from picamera.array import PiMotionAnalysis
from picamera import PiCamera
import numpy as np
from PIL import Image
from threading import Lock
from queue import Queue
from .exit_clean import exit_error
from datetime import datetime


logger = logging.getLogger()


class RpisCamera(object):
    def __init__(self, rpis):
        self.rpis = rpis
        self.lock = Lock()
        self.queue = Queue()
        self.motion_magnitude = 60
        self.motion_vectors = 10
        self.motion_framerate = 24
        self.gif_size = (800,600)
        self.motion_detection_size = (1280, 720)

        try:
            self.camera = PiCamera()
            self.camera.resolution = self.rpis.camera_image_size
            self.camera.vflip = self.rpis.camera_vflip
            self.camera.hflip = self.rpis.camera_hflip
            self.camera.led = False
        except Exception as e:
            exit_error('Camera module failed to intialise with error %s' % e)

        self.motion_detector = MotionDetector(self.camera)

    def take_photo(self, output_file):
        """
        Captures a photo and saves it disk.
        """
        try:
            with self.lock:
                while self.camera.recording:
                    time.sleep(0.1)
                self.camera.resolution = self.rpis.camera_image_size
                self.camera.capture(output_file, use_video_port=False)
        except Exception as e:
            logger.error('Failed to take photo: %s' % e)
            return False
        else:
            logger.info("Captured image: %s" % output_file)
            return True

    def take_gif(self, output_file, length, temp_directory):
        temp_jpeg_path = temp_directory + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + 'gif-part'
        jpeg_files = ['%s-%s.jpg' % (temp_jpeg_path, i) for i in range(length*3)]
        try:
            for jpeg in jpeg_files:
                with self.lock:
                    self.camera.resolution = self.gif_size
                    self.camera.capture(jpeg)
            im=Image.open(jpeg_files[0])
            jpeg_files_no_first_frame=[x for x in jpeg_files if x != jpeg_files[0]]
            ims = [Image.open(i) for i in jpeg_files_no_first_frame]
            im.save(output_file, append_images=ims, save_all=True, loop=0, duration=200)
            im.close()
            for imfile in ims:
                imfile.close()
            for jpeg in jpeg_files:
                os.remove(jpeg)
        except Exception as e:
            logger.error('Failed to create GIF: %s' % repr(e))
            return False
        else:
            logger.info("Captured gif: %s" % output_file)
            return True

    def start_motion_detection(self):
        logger.debug("Starting motion detection")
        while self.rpis.state.current is 'armed':
            time.sleep(0.1)
            while not self.lock.locked():
                if self.rpis.state.current is not 'armed':
                    break
                if self.camera.recording:
                    try:
                        self.camera.wait_recording(0.1)
                    except Exception as e:
                        logger.error('Error in wait_recording: %s' % repr(e))
                else:
                    self.camera.resolution = self.motion_detection_size
                    self.camera.framerate = 24
                    self.camera.start_recording(os.devnull, format='h264', motion_output=self.motion_detector)
                    logger.debug("Motion detection started")
            else:
                if self.camera.recording:
                    self.camera.stop_recording()
                    logger.debug("Motion detection stopped")
        else:
            if self.camera.recording:
                self.camera.stop_recording()
                logger.debug("Motion detection stopped")

    # def stop_motion_detection(self):
    #     if not self.camera.recording:
    #         return
    #     try:
    #         self.camera.stop_recording()
    #     except AttributeError:
    #         pass
    #     if not self.camera.recording:
    #         self.lock.release()
    #         logger.debug("Stopped motion detection")
    #     else:
    #         logger.error("Stop of motion detection failed")


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
