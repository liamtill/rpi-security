# -*- coding: utf-8 -*-

import datetime


def motion_detected(channel):
    """
    Capture a photo if motion is detected and the alarm state is armed
    """
    current_state = rpisecurity.state.current
    if current_state == 'armed':
        logger.info('Motion detected')
        file_prefix = config.camera_save_path + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S")
        if config.camera_mode == 'gif':
            camera_output_file = "%s.gif" % file_prefix
            take_gif(camera_output_file, config.camera_capture_length, config.camera_save_path)
            captured_from_camera.append(camera_output_file)
        elif config.camera_mode == 'photo':
            for i in range(0, config.camera_capture_length, 1):
                camera_output_file = "%s-%s.jpeg" % (file_prefix, i)
                take_photo(camera_output_file)
                captured_from_camera.append(camera_output_file)
        else:
            logger.error("Unkown camera_mode %s" % config.camera_mode)
    else:
        logger.debug('Motion detected but current_state is: %s' % current_state)
