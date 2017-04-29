# -*- coding: utf-8 -*-


def telegram_send_message(message):
    if 'telegram_chat_id' not in state:
        logger.error('Telegram failed to send message because Telegram chat_id is not set. Send a message to the Telegram bot')
        return False
    try:
        bot.sendMessage(chat_id=state['telegram_chat_id'], parse_mode='Markdown', text=message, timeout=10)
    except Exception as e:
        logger.error('Telegram message failed to send message "%s" with exception: %s' % (message, e))
    else:
        logger.info('Telegram message Sent: "%s"' % message)
        return True


def telegram_send_file(file_path):
    if 'telegram_chat_id' not in state:
        logger.error('Telegram failed to send file %s because Telegram chat_id is not set. Send a message to the Telegram bot' % file_path)
        return False
    filename, file_extension = os.path.splitext(file_path)
    try:
        if file_extension == '.mp4':
            bot.sendVideo(chat_id=state['telegram_chat_id'], video=open(file_path, 'rb'), timeout=30)
        elif file_extension == '.gif':
            bot.sendDocument(chat_id=state['telegram_chat_id'], document=open(file_path, 'rb'), timeout=30)
        elif file_extension == '.jpeg':
            bot.sendPhoto(chat_id=state['telegram_chat_id'], photo=open(file_path, 'rb'), timeout=10)
        else:
            logger.error('Uknown file not sent: %s' % file_path)
    except Exception as e:
        logger.error('Telegram failed to send file %s with exception: %s' % (file_path, e))
        return False
    else:
        logger.info('Telegram file sent: %s' % file_path)
        return True
