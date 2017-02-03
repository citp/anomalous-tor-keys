import pickle
from datetime import datetime

csv_header = "VulnerableKey_b64,Modulus_Hex,KeyType,Nickname,Fingerprint,DatePub,ip4Address,Port,TorVersion,OS,Contact,AvgBandwith,Extra,Exponent"

rsa_key_data = pickle.load(open( "All_TOR_RSA_Key_Data.pck", "rb"))
all_hex_to_b64  = pickle.load(open( "All-Hex-To-RSA.pck", "rb"))

# Get keys that have common GCDs
with open('vulnerable_moduli', 'r') as a, open('all_vulnerable_key_data.csv', 'w') as v:
    v.write(csv_header + '\n')
    for hex in a:
        rsa_key_list = all_hex_to_b64[hex.replace('\n', '')]
        key_dict = rsa_key_list[0]
        b64key = key_dict["rsa_pub_key"].replace('\n', '')
        exp = str(key_dict["exponent"])
        key_data = rsa_key_data[b64key.replace('\n', '')]
        if "key_type" in key_data:
            key_type = key_data["key_type"]
        else:
            key_type = ""
        if "nickname" in key_data:
            nickname = key_data["nickname"].replace(',', '')
        else:
            nickname = ""
        if "fingerprint" in key_data:
            fingerprint = key_data["fingerprint"]
        else:
            fingerprint = ""
        if "date" in key_data:
            date = key_data["date"].strftime("%Y%m%d")
        else:
            date = ""
        if "ip4_address" in key_data:
            ip4 = key_data["ip4_address"].replace(',', '')
        else:
            ip4 = ""
        if "port" in key_data:
            port = str(key_data["port"])
        else:
            port = ""
        if "platform" in key_data:
            platform = key_data["platform"].split(" on ")
            tor_ver = platform[0].replace(',', '')
            os = platform[1].replace(',', '')
        else:
            tor_ver = ""
            os = ""
        if "contact" in key_data:
            contact = key_data["contact"].replace(',', '')
        else:
            contact = ""
        if "bandwidth" in key_data:
            bandwidth = str(key_data["bandwidth"])
        else:
            bandwidth = ""
        if "extra" in key_data:
            extra = key_data["extra"]
        else:
            extra = ""
        csv_line = b64key+','+hex.replace('\n', '')+','+key_type+','+nickname+','+fingerprint+','+date+','+ip4+','+port+','+tor_ver+','+os+','+contact+','+bandwidth+','+extra+','+exp + '\n'
        v.write(csv_line)

# Get keys that have repeated moduli
with open('all_repeated_moduli_data.csv', 'w') as h:
    h.write(csv_header +'\n')
    for hex in all_hex_to_b64:
        rsa_key_list = all_hex_to_b64[hex.replace('\n', '')]
        if len(rsa_key_list) > 1:
            for key_dict in rsa_key_list:
                b64key = key_dict["rsa_pub_key"].replace('\n', '')
                exp = str(key_dict["exponent"])
                key_data = rsa_key_data[b64key.replace('\n', '')]
                if "key_type" in key_data:
                    key_type = key_data["key_type"]
                else:
                    key_type = ""
                if "nickname" in key_data:
                    nickname = key_data["nickname"].replace(',', '')
                else:
                    nickname = ""
                if "fingerprint" in key_data:
                    fingerprint = key_data["fingerprint"]
                else:
                    fingerprint = ""
                if "date" in key_data:
                    date = key_data["date"].strftime("%Y%m%d")
                else:
                    date = ""
                if "ip4_address" in key_data:
                    ip4 = key_data["ip4_address"].replace(',', '')
                else:
                    ip4 = ""
                if "port" in key_data:
                    port = str(key_data["port"])
                else:
                    port = ""
                if "platform" in key_data:
                    platform = key_data["platform"].split(" on ")
                    tor_ver = platform[0].replace(',', '')
                    os = platform[1].replace(',', '')
                else:
                    tor_ver = ""
                    os = ""
                if "contact" in key_data:
                    contact = key_data["contact"].replace(',', '')
                else:
                    contact = ""
                if "bandwidth" in key_data:
                    bandwidth = str(key_data["bandwidth"])
                else:
                    bandwidth = ""
                if "extra" in key_data:
                    extra = key_data["extra"]
                else:
                    extra = ""
                csv_line = b64key+','+hex.replace('\n', '')+','+key_type+','+nickname+','+fingerprint+','+date+','+ip4+','+port+','+tor_ver+','+os+','+contact+','+bandwidth+','+extra+','+exp+ '\n'
                h.write(csv_line)


