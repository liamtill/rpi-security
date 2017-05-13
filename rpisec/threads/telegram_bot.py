# -*- coding: utf-8 -*-

import logging
from datetime import datetime
from telegram.ext import Updater, CommandHandler, RegexHandler
import _thread


logger = logging.getLogger()


def telegram_bot(rpisec):
    """
    This function runs the telegram bot that responds to commands like /enable, /disable or /status.
    """
    logging.getLogger("telegram").setLevel(logging.ERROR)
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

    def error_callback(bot, update, error):
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
        dp.add_error_handler(error_callback)
        updater.start_polling(timeout=10)
    except Exception as e:
        logger.error('Telegram Updater failed to start with error {0}'.format(repr(e)))
        _thread.interrupt_main()
    else:
        logger.info("thread running")