from scapy.all import NTPExtensions, raw
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from custom_logger import log

backend = default_backend()

def decode_n(n):
    vals = []
    while n != 0:
        vals.append(n % 256)
        n = n // 256
    return bytes(vals[::-1][1:-1])

def decode_custom_ntp_packet(packet):
    raw_value = raw(packet[NTPExtensions].extensions[0].value)
    encoded = b64encode(raw_value)
    pubkey_str = b"-----BEGIN PUBLIC KEY-----\n"+encoded+b"\n-----END PUBLIC KEY-----\n" 
    pubkey = load_pem_public_key(pubkey_str,backend=backend)
    pubkey_nums = pubkey.public_numbers()
    n = pubkey_nums.n
    message = decode_n(n)
    message_len = int.from_bytes(message[0:2],"little")
    plaintext = message[2:2+message_len]
    return plaintext.decode()