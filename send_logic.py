from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey,RSAPublicNumbers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from base64 import b64decode
from scapy.all import IP, UDP, NTP, NTPExtension, NTPHeader, NTPExtensions,send
from custom_logger import log

SIGN_MESSAGE_REQUEST = 0x0602
SIGN_MESSAGE_RESPONSE = 0x8602
SIGN_MESSAGE_ERROR_RESPONSE = 0xC602

exponent = 257

backend = default_backend()

private_key = rsa.generate_private_key(
    public_exponent=exponent,
    key_size=2048,
    backend=backend
)

def encode_n(message):
    n = ord('\n')
    for b in message:
        n = (n << 8) + b
    return n

def send_message(dst, msg,server=False):
    # max len 509 bytes
    assert len(msg) <= 509, "message too long"
    bytes_val = (len(msg)).to_bytes(2, 'little')
    message = bytes_val + msg.encode() + (509-len(msg))*b'\x00'
    n = encode_n(message)
    pubkey = RSAPublicNumbers(e=exponent,n=n).public_key(backend)
    pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    raw = b64decode(b"".join(pem.split(b"\n")[1:-1]))
    msg_type = SIGN_MESSAGE_RESPONSE if server else SIGN_MESSAGE_REQUEST
    log.info(f"Sending message of type server={server} {msg}")
    extension = NTPExtension(value=raw,len=len(raw)+4,type=msg_type)
    packet = IP(dst=dst)/UDP(dport=123)/NTPHeader()/NTPExtensions(extensions=[extension])
    send(packet)