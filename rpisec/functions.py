# -*- coding: utf-8 -*-


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


def take_photo(output_file):
    """
    Captures a photo and saves it disk.
    """
    try:
        camera.capture(output_file)
    except Exception as e:
        logger.error('Failed to take photo: %s' % e)
        return False
    else:
        logger.info("Captured image: %s" % output_file)
        return True


def take_gif(output_file, length, temp_directory):
    temp_jpeg_path = temp_directory + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + 'gif-part'
    jpeg_files = ['%s-%s.jpg' % (temp_jpeg_path, i) for i in range(length*3)]
    try:
        for jpeg in jpeg_files:
            camera.capture(jpeg, resize=(800,600))
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
        logger.error('Failed to create GIF: %s' % e)
        return False
    else:
        logger.info("Captured gif: %s" % output_file)
        return True
