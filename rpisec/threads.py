# -*- coding: utf-8 -*-

import logging
import time
import sys
import os
from datetime import datetime
from .exit_clean import exit_error
from telegram.ext import Updater, CommandHandler, RegexHandler
from scapy.all import sniff


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


def capture_packets(rpisec):
    """
    This function uses scapy to sniff packets for our MAC addresses and updates
    the alarm state when packets are detected.
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    def update_time(packet):
        packet_mac = set(rpisec.mac_addresses) & set([packet[0].addr2, packet[0].addr3])
        packet_mac_str = list(packet_mac)[0]
        rpisec.state.update_last_mac(packet_mac_str)
        logger.debug('Packet detected from %s' % str(rpisec.state.last_mac))
    def calculate_filter(mac_addresses):
        mac_string = ' or '.join(mac_addresses)
        filter_text = (
            '((wlan addr2 ({0}) or wlan addr3 ({0})) '
            'and type mgt subtype probe-req) '
            'or (wlan addr1 {1} '
            'and wlan addr3 ({0}))'
        )
        return filter_text.format(mac_string, rpisec.my_mac_address)
    while True:
        logger.info("thread running")
        try:
            sniff(iface=rpisec.network_interface, store=0, prn=update_time, filter=calculate_filter(rpisec.mac_addresses))
        except Exception as e:
            exit_error('Scapy failed to sniff packets with error {0}'.format(repr(e)))


def monitor_alarm_state(rpisec):
    """
    This function monitors and updates the alarm state based on data from
    telegram and packet_capture threads.
    """
    logger.info("thread running")
    while True:
        time.sleep(0.1)
        now = time.time()
        if rpisec.state.current is not 'disabled':
            if now - rpisec.state.last_packet > rpisec.packet_timeout + 20:
                rpisec.state.update_state('armed')
            elif now - rpisec.state.last_packet > rpisec.packet_timeout:
                logger.info("Running arp_ping_macs before arming...")
                rpisec.arp_ping_macs()
            else:
                rpisec.state.update_state('disarmed')


def telegram_bot(rpisec):
    """
    This function runs the telegram bot that responds to commands like /enable, /disable or /status.
    """
    def save_chat_id(bot, update):
        if 'telegram_chat_id' not in rpisec.saved_data:
            rpisec.save_telegram_chat_id(update.message.chat_id)
            logger.debug('Set Telegram chat_id %s' % update.message.chat_id)

    def debug(bot, update):
        logger.debug('Received Telegram bot message: %s' % update.message.text)

    def check_chat_id(update):
        if 'telegram_chat_id' in rpisec.saved_data and update.message.chat_id != rpisec.saved_data['telegram_chat_id']:
            logger.debug('Ignoring Telegam update with filtered chat id %s: %s' % (update.message.chat_id, update.message.text))
            return False
        else:
            return True

    def help(bot, update):
        if check_chat_id(update):
            bot.sendMessage(update.message.chat_id, parse_mode='Markdown', text='/status: Request status\n/disable: Disable alarm\n/enable: Enable alarm\n/photo: Take a photo\n/gif: Take a gif\n', timeout=10)

    def status(bot, update):
        if check_chat_id(update):
            bot.sendMessage(update.message.chat_id, parse_mode='Markdown', text=rpisec.state.generate_status_text(), timeout=10)

    def disable(bot, update):
        if check_chat_id(update):
            rpisec.state.update_state('disabled')

    def enable(bot, update):
        if check_chat_id(update):
            rpisec.state.update_state('disarmed')

    def photo(bot, update):
        if check_chat_id(update):
            file_path = rpisec.camera_save_path + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + '.jpeg'
            rpisec.camera.take_photo(file_path)
            rpisec.telegram_send_file(file_path)

    def gif(bot, update):
        if check_chat_id(update):
            file_path = rpisec.camera_save_path + "/rpi-security-" + datetime.now().strftime("%Y-%m-%d-%H%M%S") + '.gif'
            rpisec.camera.take_gif(file_path, rpisec.camera_capture_length, rpisec.camera_save_path)
            rpisec.telegram_send_file(file_path)

    def error(bot, update, error):
        logger.error('Update "%s" caused error "%s"' % (update, error))

    try:
        updater = Updater(rpisec.telegram_bot_token)
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
    except Exception as e:
        exit_error('Telegram Updater failed to start with error {0}'.format(repr(e)))
    else:
        logger.info("thread running")
        updater.start_polling(timeout=10)
