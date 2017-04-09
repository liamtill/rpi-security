# -*- coding: utf-8 -*-

import sys
import os
import time
import yaml
import logging
from configparser import SafeConfigParser
from netaddr import IPNetwork
from netifaces import ifaddresses

logger = logging.getLogger(__name__)

class RpiConfig(object):
    """
    This class checks configuration, system state and also manages the state
    file
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

    def __init__(self, config_file, state_file):
        self.config_file = config_file
        self.state_file = state_file
        self.saved_state = self._read_state_file()
        self._parse_config_file()
        self._check_system()

        logger.debug('Config initialised: %s' % vars(self))

    def write_state_file(self, state_data):
        """
        Writes a state file to disk.
        """
        try:
            with open(self.state_file, 'w') as f:
                yaml.dump(state_data, f, default_flow_style=False)
        except Exception as e:
            logger.error('Failed to write state file %s: %s'.format(self.state_file, e))
        else:
            logger.debug('State file written: %s' % self.state_file)

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

    def _read_state_file(self):
        """
        Reads a state file from disk.
        """
        result = None
        try:
            with open(self.state_file, 'r') as stream:
                result = yaml.load(stream) or None
        except Exception as e:
            logger.error('Failed to read state file {0}: {1}'.format(self.state_file, repr(e)))
        else:
            logger.debug('State file read: {0}'.format(self.state_file))
        return result

    def _check_system(self):
        if sys.platform is not 'raspbian':
            raise Exception('Only supported on Raspbian version xx')

        if not os.geteuid() == 0:
            exit_error('%s must be run as root' % sys.argv[0])

        if not self._check_monitor_mode(self.network_interface):
            raise Exception('Monitor mode is not enabled for interface {0}'.format(self.network_interface))

        self._set_network_address()
        self._set_interface_mac_addr()

    def _check_monitor_mode(self, network_interface):
        """
        Returns True if an interface is in monitor mode
        """
        result = False
        try:
            type_file = open('/sys/class/net/%s/type' % network_interface, 'r')
            operstate_file = open('/sys/class/net/%s/operstate' % network_interface, 'r')
        except:
            pass
        else:
            if type_file.read().startswith('80') and not operstate_file.read().startswith('down'):
                result = True
        return result

    def _set_interface_mac_addr(self):
        """
        Gets the MAC address of an interface
        """
        try:
            with open('/sys/class/net/%s/address' % self.network_interface, 'r') as f:
                self.mac_address = f.read().strip()
        except:
            raise Exception('Unable to get MAC address for interface {0}'.format(self.network_interface))

    def _set_network_address(self):
        """
        Calculates the network address of an interface.
        """
        for interface in os.listdir('/sys/class/net'):
            if interface in ['lo', self.network_interface]:
                pass
            try:
                with open('/sys/class/net/%s/address' % interface, 'r') as f:
                    interface_mac_address = f.read().strip()
            except:
                pass
            else:
                if interface_mac_address == self.mac_address:
                    interface_details = ifaddresses(interface)
                    my_network = IPNetwork('%s/%s'.format(interface_details[2][0]['addr'], interface_details[2][0]['netmask']))
                    network_address = my_network.cidr
                    logger.debug('Calculated network: %s' % network_address)
                    self.network_address = str(network_address)
        if not self.network_address:
            raise Exception('Unable to get network address')
