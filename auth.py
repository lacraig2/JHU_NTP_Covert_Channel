from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom

backend = default_backend()
key = b'\x85W\xcd|.\x82\xd8\xa8\xf7\xa9\xeeJ\xc4#"e\x19\xda\x85%\xd0\xa4o\xado(`\xe9\x93nvq'
# a better nonce should be renegotiated
nonce = b'\xea\xd7\xd7{\x9eM\x17\x8cd|iCK\xf1\xa7]'
algorithm = algorithms.ChaCha20(key,nonce)
cipher = Cipher(algorithm, mode=None,backend=backend)