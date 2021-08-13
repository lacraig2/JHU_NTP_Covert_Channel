from scapy.all import NTPExtensions, raw
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from auth import cipher,backend
from base64 import b64encode
from custom_logger import log


def decode_n(n):
    vals = []
    while n != 0:
        vals.append(n % 256)
        n = n // 256
    return bytes(vals[::-1][1:-1])

def decrypt_packet(packet):
    decryptor = cipher.decryptor()
    ct = decryptor.update(packet) 
    decryptor.finalize()
    return ct

def decode_custom_ntp_packet(packet):
    raw_value = raw(packet[NTPExtensions].extensions[0].value)
    encoded = b64encode(raw_value)
    pubkey_str = b"-----BEGIN PUBLIC KEY-----\n"+encoded+b"\n-----END PUBLIC KEY-----\n" 
    pubkey = load_pem_public_key(pubkey_str,backend=backend)
    pubkey_nums = pubkey.public_numbers()
    n = pubkey_nums.n
    message = decode_n(n)
    dec_message = decrypt_packet(message)
    message_len = int.from_bytes(dec_message[0:2],"little")
    plaintext = dec_message[2:2+message_len]
    return plaintext.decode()