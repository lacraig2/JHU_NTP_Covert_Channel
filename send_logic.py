from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey,RSAPublicNumbers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from base64 import b64decode
from scapy.all import IP, UDP, NTP, NTPExtension, NTPHeader, NTPExtensions,send
from custom_logger import log
from datetime import datetime
from auth import cipher, backend


debug = False

SIGN_MESSAGE_REQUEST = 0x0602
SIGN_MESSAGE_RESPONSE = 0x8602
SIGN_MESSAGE_ERROR_RESPONSE = 0xC602

#rsa components
exponent = 257

def encode_n(message):
    n = ord('\n')
    for b in message:
        n = (n << 8) + b
    return n

def encrypt_packet(packet):
    encryptor = cipher.encryptor()
    ct = encryptor.update(packet)
    encryptor.finalize()
    return ct

def send_message(dst, msg, server=False,keylen=4096):
    # max len 509 bytes
    assert keylen==512 or keylen==1024 or keylen==2048 or keylen == 4096, "invalid RSA keysize"
    msglen = keylen // 8
    assert len(msg) <= msglen-3, f"message too long. Shouldn't be more than {msglen-3} bytes"
    bytes_val = (len(msg)).to_bytes(2, 'little')
    message = bytes_val + msg.encode() + (msglen-3-len(msg))*b'\x00'
    enc_message = encrypt_packet(message)
    n = encode_n(enc_message)
    pubkey = RSAPublicNumbers(e=exponent,n=n).public_key(backend)
    pem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    raw = b64decode(b"".join(pem.split(b"\n")[1:-1]))
    base = IP(dst=dst)/UDP(dport=123)
    if server:
        msg_type = SIGN_MESSAGE_RESPONSE
        utc = datetime.utcnow()
        mode = 4
        header = NTPHeader(mode=mode,ref=utc,orig=utc,recv=utc,sent=utc)
        extension = NTPExtension(value=raw,len=len(raw)+4,type=msg_type)
    else:
        msg_type = SIGN_MESSAGE_REQUEST
        mode = 3
        utc = None
        header = NTPHeader(mode=mode,ref=utc,orig=utc,recv=utc,sent=utc)
        extension = NTPExtension(value=raw,len=len(raw)+4,type=msg_type)
    log.info(f"Sending message of type server={server} '{msg}'")
    packet = base/header/NTPExtensions(extensions=[extension])
    send(packet)