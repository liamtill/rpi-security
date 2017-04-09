# -*- coding: utf-8 -*-


def process_photos(network_address, mac_addresses):
    """
    Monitors the captured_from_camera list for newly captured photos.
    When a new photos are present it will run arp_ping_macs to remove false positives and then send the photos via Telegram.
    After successfully sendind the photo it will also archive the photo and remove it from the list.
    """
    logger.info("thread running")
    while True:
        if len(captured_from_camera) > 0:
            if alarm_state.current == 'armed':
                arp_ping_macs(mac_addresses, network_address, repeat=3)
                for photo in list(captured_from_camera):
                    if alarm_state.current != 'armed':
                        break
                    logger.debug('Processing the photo: %s' % photo)
                    alarm_state['alarm_triggered'] = True
                    if telegram_send_file(photo):
                        archive_photo(photo)
                        captured_from_camera.remove(photo)
            else:
                logger.debug('Stopping photo processing as state is now %s' % alarm_state.current)
                for photo in list(captured_from_camera):
                    logger.info('Removing photo as it is a false positive: %s' % photo)
                    captured_from_camera.remove(photo)
                    # Delete the photo file
        time.sleep(5)


def capture_packets(network_interface, network_interface_mac, mac_addresses):
    """
    This function uses scapy to sniff packets for our MAC addresses and updates a counter when packets are detected.
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import sniff
    def update_time(packet):
        for mac_address in mac_addresses:
            if mac_address in packet[0].addr2 or mac_address in packet[0].addr3:
                alarm_state.update_last_mac(mac_address)
                break
        logger.debug('Packet detected from %s' % str(alarm_state.last_mac))
    def calculate_filter(mac_addresses):
        mac_string = ' or '.join(mac_addresses)
        return '((wlan addr2 (%(mac_string)s) or wlan addr3 (%(mac_string)s)) and type mgt subtype probe-req) or (wlan addr1 %(network_interface_mac)s and wlan addr3 (%(mac_string)s))' % { 'mac_string' : mac_string, 'network_interface_mac' : network_interface_mac }
    while True:
        logger.info("thread running")
        try:
            sniff(iface=network_interface, store=0, prn=update_time, filter=calculate_filter(mac_addresses))
        except Exception as e:
            exit_error('Scapy failed to sniff with error %s. Please check help or update scapy version' % e)


def monitor_alarm_state(packet_timeout):
    """
    This function monitors and updates the alarm state based on data from
    telegram and packet_capture threads.
    """
    logger.info("thread running")
    while True:
        time.sleep(1)
        now = time.time()
        if alarm_state.current is not 'disabled':
            if now - alarm_state.last_packet > packet_timeout + 20:
                alarm_state.update('armed')
            elif now - alarm_state.last_packet > packet_timeout:
                arp_ping_macs()
            else:
                alarm_state.update('disarmed')


def telegram_bot(token, camera_save_path, camera_capture_length, camera_mode):
    """
    This function runs the telegram bot that responds to commands like /enable, /disable or /status.
    """
    def save_chat_id(bot, update):
        if 'telegram_chat_id' not in state:
            state['telegram_chat_id'] = update.message.chat_id
            write_state_file(state_file=args.state_file, state_data=state)
            logger.debug('Set Telegram chat_id %s' % update.message.chat_id)
    def debug(bot, update):
        logger.debug('Received Telegram bot message: %s' % update.message.text)
    def check_chat_id(update):
        if update.message.chat_id != state['telegram_chat_id']:
            logger.debug('Ignoring Telegam update with filtered chat id %s: %s' % (update.message.chat_id, update.message.text))
            return False
        else:
            return True
    def help(bot, update):
        if check_chat_id(update):
            bot.sendMessage(update.message.chat_id, parse_mode='Markdown', text='/status: Request status\n/disable: Disable alarm\n/enable: Enable alarm\n/photo: Take a photo\n/gif: Take a gif\n', timeout=10)
    def status(bot, update):
        if check_chat_id(update):
            bot.sendMessage(update.message.chat_id, parse_mode='Markdown', text=prepare_status(alarm_state), timeout=10)
    def disable(bot, update):
        if check_chat_id(update):
            update_alarm_state('disabled')
    def enable(bot, update):
        if check_chat_id(update):
            update_alarm_state('disarmed')
    def photo(bot, update):
        if check_chat_id(update):
            file_path = camera_save_path + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + '.jpeg'
            take_photo(file_path)
            telegram_send_file(file_path)
    def gif(bot, update):
        if check_chat_id(update):
            file_path = camera_save_path + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + '.gif'
            take_gif(file_path, camera_capture_length, camera_save_path)
            telegram_send_file(file_path)
    def error(bot, update, error):
        logger.error('Update "%s" caused error "%s"' % (update, error))
    updater = Updater(token)
    dp = updater.dispatcher
    dp.add_handler(RegexHandler('.*', save_chat_id), group=1)
    dp.add_handler(RegexHandler('.*', debug), group=2)
    dp.add_handler(CommandHandler("help", help))
    dp.add_handler(CommandHandler("status", status))
    dp.add_handler(CommandHandler("disable", disable))
    dp.add_handler(CommandHandler("enable", enable))
    dp.add_handler(CommandHandler("photo", photo))
    dp.add_handler(CommandHandler("gif", gif))
    dp.add_error_handler(error)
    logger.info("thread running")
    updater.start_polling(timeout=10)
