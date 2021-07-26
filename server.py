#! /usr/bin/env python
import logging
from scapy.all import NTP,NTPExtensions,sniff,IP
from rich.logging import RichHandler
from send_logic import send_message, SIGN_MESSAGE_REQUEST
from receive_logic import decode_custom_ntp_packet
from custom_logger import log


def packet_callback(pkt):
    if NTP in pkt and NTPExtensions in pkt:
        if pkt[NTPExtensions].extensions[0].type == SIGN_MESSAGE_REQUEST:
            plaintext =decode_custom_ntp_packet(pkt)
            log.info(f"Received message: '{plaintext}'")
            if plaintext.startswith("echo"):
                log.info(f"Got an echo. Responding")
                # ideally the source here wouldn't be hardcoded
                send_message('192.168.10.1',plaintext[4:],server=True)

'''
This program gets a callback on packets from scapy.
'''
log.info("starting up sniffer")
sniff(prn=packet_callback, store=0)
log.info("closing sniffer and program")