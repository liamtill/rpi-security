# -*- coding: utf-8 -*-

import logging
from scapy.all import sniff
import _thread

logger = logging.getLogger()


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
            logger.error('Scapy failed to sniff packets with error {0}'.format(repr(e)))
            _thread.interrupt_main()
