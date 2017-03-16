"""
For each RSA public key, extract its hex modulo and exponent. Create
a dictionary mapping each hex modulo to a list of dictionaries. Each
sub-dictionary contains an RSA public key and its exponent. Pickle
that map.
"""
from collections import defaultdict
from base64 import b64decode
import pickle

from Crypto.PublicKey import RSA


all_public_keys = open('all_public_keys.txt', 'r')
all_hex_keys = open('all_hex_keys.txt', 'w')

hex_to_b64 = defaultdict(list)
for key64 in all_public_keys :
    keyDER = b64decode(key64.replace('\n', ''))
    keyPub = RSA.importKey(keyDER)
    hex = hex(keyPub.n, 'x')
    exp = keyPub.e

    # Write each unique hex to all_hex_keys.txt
    if hex not in hex_to_b64:
        all_hex_keys.write(hex + '\n')

    hex_to_b64[hex].append({
        'rsa_pub_key': key64,
        'exponent': exp
    })

pickle.dump(hex_to_b64, open('All-Hex-To-RSA.pck', 'wb'))

