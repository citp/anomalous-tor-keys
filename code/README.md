## Instructions for running the weak-tor-keys detection code.

Using a Linux machine: 

1. `wget https://factorable.net/fastgcd-1.0.tar.gz`
2. Unzip the file and replace the Makefile with the one found in this code repository. 
3. Follow the install instructions in the fastgcd README
4. Create a directory called archived_descriptors. This directory should contain all unzipped archived Tor relay descriptors https://collector.torproject.org/archive/relay-descriptors/server-descriptors/.
5. Run `python collect_all_tor_rsa_keys.py`
  * This will output two files: 
    * all_public_keys.txt (all of the Tor RSA public keys) 
    * All_TOR_RSA_Key_Data.pck (a pickled python dictionary with all of the Tor RSA public key metadata).
  * Note: this will take more than 24 hours to run if you are running on all archived Tor relay descriptors.
6. Manually clean up all_public_keys.txt by searching for the string “onion.” Delete malformed lines.
7. Run `python all_keys_to_hex.py`
  * This will output two files:
    * all_hex_keys.txt (unique list of all RSA public key moduli, in hex) 
    * All-Hex-To-RSA.pck (a python pickled dictionary that maps hex moduli to a list of dictionaries. Each sub-dictionary contains an RSA public key and its exponent. All-Hex-To-RSA.pck will catch moduli that map to more than one RSA public key).
8. Run `./fastgcd all_hex_keys.txt`
  * This will output two files:
    * vulnerable_moduli
    * gcds
  *  Please refer to fastgcd README for descriptions of each.
9. Run `python vulnerable_key_data_to_csv.py`
  * This outputs two files:
    * all_vulnerable_key_data.csv (csv file containing all keys with shared GCD and their corresponding metadata)
    * all_repeated_moduli_data.csv (csv file containing all keys with repeated moduli and their corresponding metadata and exponent)
