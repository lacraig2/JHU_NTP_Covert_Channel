from scapy.all import IP, UDP, NTP, NTPExtension, NTPHeader, NTPExtensions,send
from sys import stdin
from random import randint
import logging
from rich.logging import RichHandler
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey,RSAPublicNumbers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from base64 import b64decode

backend = default_backend()

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)

log = logging.getLogger("rich")

#destination server
dest = '127.0.0.1'

SIGN_MESSAGE_REQUEST = 0x0602
SIGN_MESSAGE_RESPONSE = 0x8602
SIGN_MESSAGE_ERROR_RESPONSE = 0xC602

exponent = 257

private_key = rsa.generate_private_key(
    public_exponent=exponent,
    key_size=2048,
    backend=backend
)

'''
Here we make a DNS request with a specific site as encoded by data from our 
site list.
'''

def encode_n(message):
    n = ord('\n')
    for b in message:
        n = (n << 8) + b
    return n



def send_message(msg):
    # max len 509 bytes
    assert len(msg) <= 509, "message too long"
    bytes_val = (len(msg)).to_bytes(2, 'little')
    message = bytes_val + msg.encode() + (509-len(msg))*b'\x00'
    log.info(f"Sending message {message}")
    n = encode_n(message)
    pubkey = RSAPublicNumbers(e=exponent,n=n).public_key(backend)
    pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    raw = b64decode(b"".join(pem.split(b"\n")[1:-1]))
    extension = NTPExtension(value=raw,len=len(raw)+4,type=SIGN_MESSAGE_REQUEST)
    packet = IP(dst='192.168.86.10')/UDP(dport=123)/NTPHeader()/NTPExtensions(extensions=[extension])
    send(packet)


log.info("starting up client...")
'''
Read one character at a time from stdin. Convert and send with scapy.
'''
buf = ""

while True:
    try:
        c = stdin.read(1)
    except KeyboardInterrupt:
        break
    if c == '\n':
        send_message(buf)
        buf = ""
    else:
        buf += c

