# -*- coding: utf-8 -*-

import time
import threading
import logging
from datetime import timedelta


logger = logging.getLogger(__name__)


class RpiAlarmState(object):
    """
    This class repressents the current alarm state, manages changes to the state
    and exports state information for external use.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.alarm_triggered = False
        self.current = 'disarmed'
        self.previous = 'Not running'
        self.last_change = time.time()
        self.last_packet = None
        self.last_mac = None

    def update_state(self, new_state):
        assert new_state in ['armed', 'disarmed', 'disabled']
        if new_state != self.current:
            with self.lock:
                self.previous = self.current
                self.current = new_state
                self.last_change = time.time()
                logger.info("rpi-security is now %s" % self.current)

    def update_last_mac(self, mac):
        with self.lock:
            self.last_mac = mac
            self.last_packet = time.time()

    def _get_readable_delta(self, then, now=time.time()):
        td = timedelta(seconds=now - then)
        days, hours, minutes = td.days, td.seconds // 3600, td.seconds // 60 % 60
        text = '%s minutes' % minutes
        if hours > 0:
            text = '%s hours and ' % hours + text
            if days > 0:
                text = '%s days, ' % days + text
        return text

    def generate_status_text(self):
        return """*rpi-security status*
                Current state: _{0}_
                Last state: _{1}_
                Last change: _{2} ago_
                Uptime: _{3}_
                Last MAC detected: _{4} {5} ago_
                Alarm triggered: _{6}_
                """.format(
                    self.current,
                    self.previous,
                    _get_readable_delta(self.last_change),
                    _get_readable_delta(self.start_time),
                    self.last_mac,
                    _get_readable_delta(self.last_packet),
                    self.alarm_triggered
                )
