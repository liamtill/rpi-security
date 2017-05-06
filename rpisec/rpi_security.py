# -*- coding: utf-8 -*-

import sys
import os
import time
import yaml
import logging
import threading
from configparser import SafeConfigParser
from netaddr import IPNetwork
from netifaces import ifaddresses
from datetime import timedelta
from .exit_clean import exit_error

from telegram import Bot as TelegramBot


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import srp, Ether, ARP
from scapy.all import conf as scapy_conf
scapy_conf.promisc=0
scapy_conf.sniff_promisc=0

logger = logging.getLogger()

class RpiState(object):
    def __init__(self, rpis):
        self.rpis = rpis
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.current = 'disarmed'
        self.previous = 'Not running'
        self.last_change = time.time()
        self.last_packet = time.time()
        self.last_mac = None
        self.triggered = False

    def update_state(self, new_state):
        assert new_state in ['armed', 'disarmed', 'disabled']
        if new_state != self.current:
            with self.lock:
                self.previous = self.current
                self.current = new_state
                self.last_change = time.time()
                self.rpis.telegram_send_message("rpi-security is now {0}".format(self.current))
                logger.info("rpi-security is now {0}".format(self.current))

    def update_triggered(self, triggered):
        with self.lock:
            self.triggered = triggered

    def update_last_mac(self, mac):
        with self.lock:
            self.last_mac = mac
            self.last_packet = time.time()

    def _get_readable_delta(self, then, now=None):
        if not now:
            now = time.time()
        td = timedelta(seconds=now - then)
        days, hours, minutes = td.days, td.seconds // 3600, td.seconds // 60 % 60
        text = '%s minutes' % minutes
        if hours > 0:
            text = '%s hours and ' % hours + text
            if days > 0:
                text = '%s days, ' % days + text
        return text

    def generate_status_text(self):
        return """*rpi-security status* \
                \nCurrent state: _{0}_ \
                \nLast state: _{1}_ \
                \nLast change: _{2} ago_ \
                \nUptime: _{3}_ \
                \nLast MAC detected: _{4} {5} ago_ \
                \nAlarm triggered: _{6}_ \
                """.format(
                    self.current,
                    self.previous,
                    self._get_readable_delta(self.last_change),
                    self._get_readable_delta(self.start_time),
                    self.last_mac,
                    self._get_readable_delta(self.last_packet),
                    self.triggered
                )



class RpiSecurity(object):
    """
    xxx
    """
    default_config = {
        'camera_save_path': '/var/tmp',
        'network_interface': 'mon0',
        'packet_timeout': '700',
        'debug_mode': 'False',
        'pir_pin': '14',
        'camera_vflip': 'False',
        'camera_hflip': 'False',
        'camera_image_size': '1024x768',
        'camera_mode': 'video',
        'camera_capture_length': '3'
    }

    def __init__(self, config_file, data_file):
        self.config_file = config_file
        self.data_file = data_file
        self.saved_data = self._read_data_file()
        self._parse_config_file()
        self._check_system()
        self.state = RpiState(self)

        try:
            self.bot = TelegramBot(token=self.telegram_bot_token)
        except Exception as e:
            raise Exception('Failed to connect to Telegram with error: %s' % repr(e))

        logger.debug('Initialised: %s' % vars(self))

    def _read_data_file(self):
        """
        Reads a data file from disk.
        """
        result = None
        try:
            with open(self.data_file, 'r') as stream:
                result = yaml.load(stream) or {}
        except Exception as e:
            logger.error('Failed to read data file {0}: {1}'.format(self.data_file, repr(e)))
        else:
            logger.debug('Data file read: {0}'.format(self.data_file))
        return result

    def arp_ping_macs(self, repeat=3):
        """
        Performs an ARP scan of a destination MAC address to try and determine if they are present on the network.
        """
        def _arp_ping(mac_address):
            result = False
            answered,unanswered = srp(Ether(dst=mac_address)/ARP(pdst=self.network_address), timeout=1, verbose=False)
            if len(answered) > 0:
                for reply in answered:
                    if reply[1].hwsrc == mac_address:
                        if type(result) is not list:
                            result = []
                        result.append(str(reply[1].psrc))
                        result = ', '.join(result)
            return result
        while repeat > 0:
            for mac_address in self.mac_addresses:
                result = _arp_ping(mac_address)
                if result:
                    logger.debug('MAC %s responded to ARP ping with address %s' % (mac_address, result))
                    break
                else:
                    logger.debug('MAC %s did not respond to ARP ping' % mac_address)
            if repeat > 1:
                time.sleep(2)
            repeat -= 1

    def save_telegram_chat_id(self, chat_id):
        """
        Saves the telegram chat ID to the data file
        """
        try:
            self.saved_data['telegram_chat_id'] = chat_id
            with open(self.data_file, 'w') as f:
                yaml.dump({'telegram_chat_id': chat_id}, f, default_flow_style=False)
        except Exception as e:
            logger.error('Failed to write state file %s: %s'.format(self.data_file, e))
        else:
            logger.debug('State file written: %s' % self.data_file)

    def _parse_config_file(self):
        def _str2bool(v):
            return v.lower() in ("yes", "true", "t", "1")

        cfg = SafeConfigParser(defaults=self.default_config)
        cfg.read(self.config_file)

        for k, v in cfg.items('main'):
            setattr(self, k, v)

        self.debug_mode = _str2bool(self.debug_mode)
        self.camera_vflip = _str2bool(self.camera_vflip)
        self.camera_hflip = _str2bool(self.camera_hflip)
        self.pir_pin = int(self.pir_pin)
        self.camera_image_size = tuple([int(x) for x in self.camera_image_size.split('x')])
        self.camera_capture_length = int(self.camera_capture_length)
        self.camera_mode = self.camera_mode.lower()
        self.packet_timeout = int(self.packet_timeout)
        self.mac_addresses = self.mac_addresses.lower().split(',')

    def _check_system(self):
        if not os.geteuid() == 0:
            exit_error('%s must be run as root' % sys.argv[0])

        if not self._check_monitor_mode():
            raise Exception('Monitor mode is not enabled for interface {0} or interface does not exist'.format(self.network_interface))

        self._set_interface_mac_addr()
        self._set_network_address()

    def _check_monitor_mode(self):
        """
        Returns True if an interface is in monitor mode
        """
        result = False
        try:
            type_file = open('/sys/class/net/%s/type' % self.network_interface, 'r')
            operdata_file = open('/sys/class/net/%s/operstate' % self.network_interface, 'r')
        except:
            pass
        else:
            if type_file.read().startswith('80') and not operdata_file.read().startswith('down'):
                result = True
        return result

    def _set_interface_mac_addr(self):
        """
        Gets the MAC address of an interface
        """
        try:
            with open('/sys/class/net/%s/address' % self.network_interface, 'r') as f:
                self.my_mac_address = f.read().strip()
        except FileNotFoundError:
            raise Exception('Interface {0} does not exist'.format(self.network_interface))
        except Exception:
            raise Exception('Unable to get MAC address for interface {0}'.format(self.network_interface))

    def _set_network_address(self):
        """
        Finds the corresponding normal interface for a monitor interface and
        then calculates the subnet address of this interface
        """
        for interface in os.listdir('/sys/class/net'):
            if interface in ['lo', self.network_interface]:
                continue
            try:
                with open('/sys/class/net/%s/address' % interface, 'r') as f:
                    interface_mac_address = f.read().strip()
            except:
                pass
            else:
                if interface_mac_address == self.my_mac_address:
                    interface_details = ifaddresses(interface)
                    my_network = IPNetwork('{0}/{1}'.format(interface_details[2][0]['addr'], interface_details[2][0]['netmask']))
                    network_address = my_network.cidr
                    logger.debug('Calculated network {0} from interface {1}'.format(network_address, interface))
                    self.network_address = str(network_address)
        if not hasattr(self, 'network_address'):
            raise Exception('Unable to get network address for interface {0}'.format(self.network_interface))

    def telegram_send_message(self, message):
        if 'telegram_chat_id' not in self.saved_data:
            logger.error('Telegram failed to send message because Telegram chat_id is not set. Send a message to the Telegram bot')
            return False
        try:
            self.bot.sendMessage(chat_id=self.saved_data['telegram_chat_id'], parse_mode='Markdown', text=message, timeout=10)
        except Exception as e:
            logger.error('Telegram message failed to send message "%s" with exception: %s' % (message, e))
        else:
            logger.info('Telegram message Sent: "%s"' % message)
            return True

    def telegram_send_file(self, file_path):
        if 'telegram_chat_id' not in rpisec.saved_data:
            logger.error('Telegram failed to send file %s because Telegram chat_id is not set. Send a message to the Telegram bot' % file_path)
            return False
        filename, file_extension = os.path.splitext(file_path)
        try:
            if file_extension == '.mp4':
                bot.sendVideo(chat_id=self.saved_data['telegram_chat_id'], video=open(file_path, 'rb'), timeout=30)
            elif file_extension == '.gif':
                bot.sendDocument(chat_id=self.saved_data['telegram_chat_id'], document=open(file_path, 'rb'), timeout=30)
            elif file_extension == '.jpeg':
                bot.sendPhoto(chat_id=self.saved_data['telegram_chat_id'], photo=open(file_path, 'rb'), timeout=10)
            else:
                logger.error('Uknown file not sent: %s' % file_path)
        except Exception as e:
            logger.error('Telegram failed to send file %s with exception: %s' % (file_path, e))
            return False
        else:
            logger.info('Telegram file sent: %s' % file_path)
            return True