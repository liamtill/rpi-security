# -*- coding: utf-8 -*-

import logging
import time


logger = logging.getLogger()


def process_photos(rpisec):
    """
    Monitors the captured_from_camera list for newly captured photos.
    When a new photos are present it will run arp_ping_macs to remove false positives and then send the photos via Telegram.
    After successfully sendind the photo it will also archive the photo and remove it from the list.
    """
    logger.info("thread running")
    while True:
        if not rpisec.camera.queue.empty():
            if rpisec.state.current == 'armed':
                rpisec.arp_ping_macs()
                while True:
                    photo = rpisec.camera.queue.get()
                    if photo is None or rpisec.state.current != 'armed':
                        break
                    logger.debug('Processing the photo: %s' % photo)
                    rpisec.state.update_triggered(True)
                    if rpisec.telegram_send_file(photo):
                        archive_photo(photo)
                        photo.task_done()
            else:
                logger.debug('Stopping photo processing as state is now %s and clearing queue' % rpisec.state.current)
                rpisec.camera.queue.clear()
        time.sleep(0.1)
