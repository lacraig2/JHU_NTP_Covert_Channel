#! /usr/bin/env python
from scapy.all import UDP, IP, sniff, DNS,NTP,NTPExtensions
from scapy.all import *
import logging
from rich.logging import RichHandler
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from base64 import b64encode

backend = default_backend()


FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)

log = logging.getLogger("rich")

def decode_n(n):
    vals = []
    while n != 0:
        vals.append(n % 256)
        n = n // 256
    return bytes(vals[::-1][1:])

def packet_callback(pkt):
    if NTP in pkt and NTPExtensions in pkt:
        raw_value = raw(pkt[NTPExtensions].extensions[0].value)
        encoded = b64encode(raw_value)
        pubkey_str = b"-----BEGIN PUBLIC KEY-----\n"+encoded+b"\n-----END PUBLIC KEY-----\n" 
        pubkey = load_pem_public_key(pubkey_str,backend=backend)
        pubkey_nums = pubkey.public_numbers()
        n = pubkey_nums.n
        message = decode_n(n)
        message_len = int.from_bytes(message[0:2],"little")
        plaintext = message[2:2+message_len]
        log.info(f"Received message {plaintext} {len(plaintext)}")

'''
This program gets a callback on packets from scapy.
'''
log.info("starting up sniffer")
sniff(prn=packet_callback, store=0)
log.info("closing sniffer and program")