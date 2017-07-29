import cv2
import time
import datetime
import picamera
from picamera.array import PiRGBArray
import urllib
import requests
import numpy as np

class VideoFeeds(object):
    """
    This class is for loading the video feeds to monitor
    """
    def __init__(self, picam, usbcams, ip_addresses):
        self.picam = picam
        self.ip_addresses = ip_addresses
        self.usbcams = usbcams

    def get_picam_feed(self, camera_image_size, camera_hflip, camera_vflip, led=False):
        """
        Load the RPi cam feed
        """
        self.camera = picamera.PiCamera()
        self.camera_image_size = camera_image_size
        self.hflip = camera_hflip
        self.vflip = camera_vflip
        self.led = led
        self.camera.resolution = self.camera_image_size
        self.camera.vflip = self.vlfip
        self.camera.hflip = self.hflip
        self.camera.led = self.led
        self.capture = PiRGBArray(self.camera, size=self.camera_image_size)
        return [self.camera, self.capture]

    def make_ip_stream(self, ip_addr):
        """
        Makes stream for IP camera access
        """
        if requests.get('http://'+str(ip_addr)).status_code != 200:
            return False
        else:
            bytes = ''
            return [bytes, urllib.urlopen('http://'+str(ip_addr))]

    def get_ip_feed(self, bytes, stream):
        """
        Returns frame from IP camera stream and bytes from stream.
        """
        grabbed = False
        while not grabbed:
            bytes += stream.read(1024)
            a = bytes.find('\xff\xd8')
            b = bytes.find('\xff\xd9')
            if a != -1 and b != -1:
                jpg = bytes[a:b + 2]
                bytes = bytes[b + 2:]
                frame = cv2.imdecode(np.fromstring(jpg, dtype=np.uint8), cv2.CV_LOAD_IMAGE_COLOR)  # put cv2.IMREAD_COLOR for opencv3
                grabbed = True
        return bytes, frame

    def get_usbcam_feed(self, num):
        """
        Get usb cam capture feed
        """
        return cv2.VideoCapture(num)

    def start_feeds(self, camera_image_size, camera_hflip, camera_vflip):
        """
        This function starts all the video feeds for monitoring
        """
        self.feeds = {}
        numfeeds = 0
        attempts = 3
        active = True
        msg = ''

        if self.picam: # start picam feed
            for at in range(attempts):
                self.feeds['picam'] = self.get_picam_feed(camera_image_size, camera_hflip, camera_vflip)
                if self.feeds['picam'][0]._check_camera_open(): # needs to be tested
                    msg += 'Pi cam \n'
                    numfeeds += 1
                    break
                else:
                    msg += 'Pi cam failed to initialise \n'
                    active = False
            time.sleep(1)
        else:
            self.feeds['picam'] = []
        if self.usbcams > 0: # start usb cam feeds
            tmp = []
            for i in range(self.usbcams):
                for at in range(attempts):
                    tmp.append(self.get_usbcam_feed(i))
                    if tmp[i].isOpened():
                        numfeeds += 1
                        msg += 'USB camera ' + str(i) + ' initialised \n'
                        break
                    else:
                        msg += 'USB camera ' + str(i)+ ' failed to initialise \n'
                        active = False
                    # resolution wont set
                time.sleep(1)
            self.feeds['usbcam'] = tmp

        else:
            self.feeds['usbcam'] = []
        if self.ip_addresses != '': # start ip webcam feeds
            tmp = []
            if type(self.ip_addresses) == str:
                for at in range(attempts):
                    tmp.append(self.make_ip_stream((self.ip_addresses)))
                    if tmp[i]:
                        numfeeds += 1
                        numips = 1
                        msg += 'IP camera ' + str(self.ip_addresses) + ' initialised \n'
                        break
                    else:
                        msg += 'IP ' + str(self.ip_addresses)+ ' camera failed to initialise \n'
                        active = False
            else:
                numips = 0
                for ip_addr in self.ip_addresses:
                    for at in range(attempts):
                        tmp.append(self.make_ip_stream((ip_addr)))
                        if tmp[i]:
                            numfeeds += 1
                            numips += 1
                            msg += 'IP camera ' + str(ip_addr) + ' initialised \n'
                            break
                            # maybe set resolution
                        else:
                            msg += 'IP camera ' + str(self.ip_addresses) + ' failed to initialise \n'
                            active = False
                    time.sleep(1)
            self.feeds['ipcam'] = tmp
        else:
            self.feeds['ipcam'] = []

        time.sleep(1)

        topop = []
        for key, val in self.feeds.iteritems():
            if not val:
                topop.append(key)
        map(self.feeds.pop, topop)

        return self.feeds, numfeeds, msg, active

    def getframes(self, feeds, feed):
        """
        Get frame from current feed
        """
        frames = []
        if feed == 'picam':  # from pi cam
            f = feeds[feed][0].capture(feeds[feed][1], format="bgr", use_video_port=True)
            # using the video port is faster than the image port per the API docs
            frames.append(f.array)
        if feed == 'usbcam':  # usb cam
            for i, cam in enumerate(feeds[feed]):
                (snapped, frame) = cam.read()
                frames.append(frame)
        if feed == 'ipcam':  # ip cam
            for i, cam in enumerate(feeds[feed]):
                cam[0], frame = self.get_ip_feed(cam[0], cam[1])
                frames.append(frame)

        return frames

    def saveframe(self, output_file, frame):
        """
        Save frame to jpeg file
        """
        cv2.imwrite(output_file, frame)

    def getactivefeed(self, activefeed):
        """
        Get the active feed motion was detected on for capturing image
        """
        import re
        m = re.match(r"([a-z]+)([0-9]+)", activefeed, re.I)
        thefeed, thenum = m.groups(0)[0], int(m.groups(0)[1]) # extracts the active feed
        feed = {}
        if thefeed == 'picam':
            feed['picam'] = [self.feeds['picam']] # make link to pi cam feed
        if thefeed == 'usbcam':
            feed['usbcam'] = [self.feeds['usbcam'][thenum]] # make link to usb cam feed
        if thefeed == 'ipcam': # make seperate ip stream to access frame
            tmp = []
            if type(self.ip_addresses) == str:
                tmp.append(self.make_ip_stream(self.ip_addresses))
            else:
                tmp.append(self.make_ip_stream(self.ip_addresses[thenum]))
            feed['ipcam'] = tmp

        return feed, thefeed

    def timestamp(self, frame):
        """
        Put timestamp on frame
        """
        cv2.putText(frame, datetime.datetime.now().strftime("%A %d %B %Y %H:%M:%S"), (10, 40),
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
        return frame

    def cleanup(self, feeds):
        # Cleanup feeds for exit
        for feed in feeds:
            if feed == 'picam':
                feed[0].close()
            if feed == 'usbcam':  # usb cam
                for i, cam in enumerate(feeds[feed]):
                    cam.release()
            if feed == 'ipcam':  # ip cam
                for i, cam in enumerate(feeds[feed]):
                    cam[1].close()

class MotionDetector(object):
    """
    Class for the motion detector objects used to detect motion in video feed frames
    """
    def __init__(self, deltathresh, minareathresh):
        self.avg = None
        self.deltathresh = deltathresh
        self.minareathresh = minareathresh
        self.kernel = np.ones((5, 5),
                np.uint8)  # make kernel for erode and dilate. Can play with size of array but 5,5 seems to work good.

    def detect_motion(self, frame):
        """
        Uses pi cam, USB webcam or IP webcam to detect motion. OpenCV is used to detect changes in
        frames by using a weighted average allowing it to adjust to lighting, shadows.
        """
        # possible resize as using the full image resolution may be inefficient!
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)  # convert to grayscale
        # smooth image, to average pixel intensities across a box of size 21x21, can play with this but 21x21 seems to work nice
        # helps smooth out noise.
        gray = cv2.GaussianBlur(gray, (21, 21), 0)
        if self.avg is None:  # init avg with initial values if None
            self.avg = gray.copy().astype("float")
            return False

        # accumulate weighted average between current frame and previous frames
        # then calc absolute difference between current frame and running average
        cv2.accumulateWeighted(gray, self.avg, 0.5)  # 0.5 is a default weighting to use between frames
        delta = cv2.absdiff(gray, cv2.convertScaleAbs(self.avg))  # difference between frame and average
        # make image of black and white if pixels over given threshold
        thresh = cv2.threshold(delta, self.deltathresh, 255, cv2.THRESH_BINARY)[1]
        thresh = cv2.erode(thresh, self.kernel,
                           iterations=2)  # do erosion, useful for removing white noise, as well as gaussian blur above
        thresh = cv2.dilate(thresh, self.kernel, iterations=2)  # dilate white, now noise is removed. As per..
        # http://opencv-python-tutroals.readthedocs.io/en/latest/py_tutorials/py_imgproc/py_morphological_ops/py_morphological_ops.html

        # find contours connecting continous points
        (cnts, _) = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for c in cnts:
            if cv2.contourArea(c) > self.minareathresh:
                return True
            else: # if contour area is smaller than min_area_thresh then ignore
                return False