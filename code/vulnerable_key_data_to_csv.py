import csv
import pickle


rsa_key_data = pickle.load(open('All_TOR_RSA_Key_Data.pck', 'rb'))
all_hex_to_b64  = pickle.load(open('All-Hex-To-RSA.pck', 'rb'))

vulnerable_moduli = open('vulnerable_moduli', 'r')

header_row = [
    'VulnerableKey_b64', 'Modulus_Hex', 'KeyType', 'Nickname', 'Fingerprint',
    'DatePub', 'ip4Address', 'Port', 'TorVersion', 'OS', 'Contact',
    'AvgBandwith', 'Extra', 'Exponent'
]

def get_row_from_key_data(key_data):
    """Get the CSV row corresponding to a given key data."""
    if 'platform' in key_data:
        platform = key_data['platform'].split(' on ')
        tor_ver = platform[0]
        os = platform[1]
    else:
        tor_ver = None
        os = None

    return [
        b64key,
        hex.replace('\n', ''),
        key_data.get('key_type'),
        key_data.get('nickname'),
        key_data.get('fingerprint'),
        key_data.get('date') and key_data['date'].strftime('%Y%m%d'),
        key_data.get('ip4_address'),
        key_data.get('port'),
        tor_ver,
        os,
        key_data.get('contact'),
        key_data.get('bandwidth'),
        key_data.get('extra'),
        exp
    ]

# Write keys that have common GCDs.
csv_writer = csv.writer(open('all_vulnerable_key_data.csv', 'wb'))
csv_writer.writerow(header_row)
for hex in vulnerable_moduli:
    rsa_key_list = all_hex_to_b64[hex.replace('\n', '')]

    key_dict = rsa_key_list[0]
    b64key = key_dict['rsa_pub_key'].replace('\n', '')
    exp = key_dict['exponent']
    key_data = rsa_key_data[b64key.replace('\n', '')]

    csv_writer.writerow(get_row_from_key_data(key_data))

# Write keys that have repeated moduli.
csv_writer = csv.writer(open('all_repeated_moduli_data.csv', 'wb'))
csv_writer.writerow(header_row)
for hex in all_hex_to_b64:
    rsa_key_list = all_hex_to_b64[hex.replace('\n', '')]
    if len(rsa_key_list) <= 1:
        continue

    for key_dict in rsa_key_list:
        b64key = key_dict['rsa_pub_key'].replace('\n', '')
        exp = key_dict['exponent']
        key_data = rsa_key_data[b64key.replace('\n', '')]

        csv_writer.writerow(get_row_from_key_data(key_data))

