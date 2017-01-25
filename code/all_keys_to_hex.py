from Crypto.PublicKey import RSA
from base64 import b64decode
import pickle

hex_to_b64 = dict()

with open('all_hex_keys.txt', 'w') as g:
    with open('all_public_keys.txt', 'r') as f:
        for key64 in f:
            keyDER = b64decode(key64.replace('\n', ''))
            keyPub = RSA.importKey(keyDER)
            hex = format(keyPub.n, 'x')
            exp = keyPub.e
            if hex in hex_to_b64:
                rsa_key = dict()
                rsa_key["rsa_pub_key"] = key64
                rsa_key["exponent"] = exp
                hex_to_b64[hex].append(rsa_key)
            else:
                list_rsa_keys = list()
                rsa_key = dict()
                rsa_key["rsa_pub_key"] = key64
                rsa_key["exponent"] = exp
                list_rsa_keys.append(rsa_key)
                hex_to_b64[hex] = list_rsa_keys
                g.write(hex + '\n')

pickle.dump(hex_to_b64, open("All-Hex-To-RSA.pck", "wb" ))

