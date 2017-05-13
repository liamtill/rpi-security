# -*- coding: utf-8 -*-

import logging
import time


logger = logging.getLogger()


def monitor_alarm_state(rpisec):
    """
    This function monitors and updates the alarm state based on data from
    telegram and packet_capture threads.
    """
    logger.info("thread running")
    while True:
        time.sleep(0.1)
        rpisec.state.check()
        if rpisec.state.current is 'armed':
            rpisec.camera.start_motion_detection()
        else:
            rpisec.camera.stop_motion_detection()
