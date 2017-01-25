# Collect all RSA public keys: recent, archived, signing key and onion key
# Create a dictionary that maps RSA public keys to metadata. Pickle this dictionary.
from stem.descriptor.remote import DescriptorDownloader
from stem.descriptor.reader import DescriptorReader
import pickle

downloader = DescriptorDownloader()
descriptors = ['archived_descriptors/']
rsa_key_data = dict()

# Get RSA keys from recent server descriptors
for desc_r in downloader.get_server_descriptors():
    # Load metadata with relay information: nickname, fingerprint, published, address, or_port, platform, contact, average_bandwith, extra_info_digest
    metadata = dict()
    if desc_r.nickname is not None:
        metadata["nickname"] = desc_r.nickname
    if desc_r.fingerprint is not None:
        metadata["fingerprint"] = desc_r.fingerprint
    if desc_r.published is not None:
        metadata["date"] = desc_r.published
    if desc_r.address is not None:
        metadata["ip4_address"] = desc_r.address
    if desc_r.or_port is not None:
        metadata["port"] = desc_r.or_port
    if desc_r.platform is not None:
        metadata["platform"] = desc_r.platform
    if desc_r.contact is not None:
        metadata["contact"] = desc_r.contact
    if desc_r.average_bandwidth is not None:
        metadata["bandwidth"] = desc_r.average_bandwidth
    if desc_r.extra_info_digest is not None:
        metadata["extra"] = desc_r.extra_info_digest

    onion_metadata = metadata.copy()

    pubKey = desc_r.signing_key
    if pubKey != None:
        pubKey = pubKey.replace('\n', '')
        pubKey = pubKey.replace('-----BEGIN RSA PUBLIC KEY-----', '')
        pubKey = pubKey.replace('-----END RSA PUBLIC KEY-----', '')
        metadata["key_type"] = "signing key"
        rsa_key_data[pubKey] = metadata
    
    onionKey = desc_r.onion_key
    if onionKey != None:
        onionKey = onionKey.replace('\n', '')
        onionKey = onionKey.replace('-----BEGIN RSA PUBLIC KEY-----', '')
        onionKey = onionKey.replace('-----END RSA PUBLIC KEY-----', '')
        onion_metadata["key_type"] = "onion key"
        rsa_key_data[onionKey] = onion_metadata

# Get RSA keys from archived server descriptors
with DescriptorReader(descriptors) as reader:
    for desc_a in reader:
        metadata = dict()
        if desc_a.nickname is not None:
            metadata["nickname"] = desc_a.nickname
        if desc_a.fingerprint is not None:
            metadata["fingerprint"] = desc_a.fingerprint
        if desc_a.published is not None:
            metadata["date"] = desc_a.published
        if desc_a.address is not None:
            metadata["ip4_address"] = desc_a.address
        if desc_a.or_port is not None:
            metadata["port"] = desc_a.or_port
        if desc_a.platform is not None:
            metadata["platform"] = desc_a.platform
        if desc_a.contact is not None:
            metadata["contact"] = desc_a.contact
        if desc_a.average_bandwidth is not None:
            metadata["bandwidth"] = desc_a.average_bandwidth
        if desc_a.extra_info_digest is not None:
            metadata["extra"] = desc_a.extra_info_digest

        onion_metadata = metadata.copy()
        
        pubKey = desc_a.signing_key
        if pubKey is not None:
            pubKey = pubKey.replace('\n', '')
            pubKey = pubKey.replace('-----BEGIN RSA PUBLIC KEY-----', '')
            pubKey = pubKey.replace('-----END RSA PUBLIC KEY-----', '')
            metadata["key_type"] = "signing key"
            rsa_key_data[pubKey] = metadata
    
        onionKey = desc_a.onion_key
        if onionKey is not None:
            onionKey = onionKey.replace('\n', '')
            onionKey = onionKey.replace('-----BEGIN RSA PUBLIC KEY-----', '')
            onionKey = onionKey.replace('-----END RSA PUBLIC KEY-----', '')
            onion_metadata["key_type"] = "onion key"
            rsa_key_data[onionKey] = onion_metadata

with open('all_public_keys.txt', 'w') as f:
    for key in rsa_key_data:
        f.write(key + '\n')

pickle.dump(rsa_key_data, open( "All_TOR_RSA_Key_Data.pck", "wb" ) )
