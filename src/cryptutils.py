'''
Created on 15 Dec 2019

@author: gualtiero
'''

import os
import base64
import json

from constants import CONFIG_FILE, PRE_SALT
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def _has_configuration(config_file):
    """Checks if the configurations file CONFIG_FILE exists
    input:
    config_file    a path to the configuration file
    output:
    Boolean indicating if the configuration file exists"""
    return os.path.exists(config_file)

def _get_encripted_key(config_password):
    """Produces an encripted and repeatible key
       combining the PRE_SALT string and a user password specific for 
       configuration generation
       input:
       config_password    a password used to make the unique configuration file
       output:
       the encrypted key used for encrypting data"""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=PRE_SALT,
                     iterations=100000,
                     backend=default_backend()
                     )
    key = base64.urlsafe_b64encode(kdf.derive(config_password))
    return key

def configure(config_password,config_file = CONFIG_FILE):
    """This produce a static salt for cryptography. This salt is stored in the configuration file  on the client machine.
       If the configuration file exists, this function returns an error message, since reconfiguing the salt
       requires changes to all the encripted information in the remote DB
       input:
       config_password  the memorable password generating the salt
       config_file      the configuration file, defaults to fixed location in CONFIG_FILE
       """
    if _has_configuration(config_file):
        raise RuntimeError("Found pre-existing configuration in %s. To reconfigure the secretes call reconfigure function",config_file)
    
    ekey=_get_encripted_key(config_password.encode("latin1")).decode("latin1")
    conf = {'key': ekey}
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    with open(config_file, 'w') as cfile:
        json.dump(conf, cfile)
        
def get_configuration(config_file = CONFIG_FILE):
    """Read the configuration file and returns it as a dictionary
    input:
    config_file    a path to the configuration file
    output:
    A data dictionary containing the configuration"""
    with open(config_file, 'r') as cfile:
        return json.load(cfile)
    
def encrypt(secret, mem_pswd,config_file = CONFIG_FILE):
    """Encrypts a secrets using a fixed key and a memorable password
    input:
    secret       text to encrypt (unicode)
    mem_pswd     memorable password (unicode)
    config_file  a path to the configuration file containing the encrypted key
    output:
    The encrypted (byte string) value 
    """
    data = get_configuration(config_file)
    salt = data['key'].encode('latin1')
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=100000,
                     backend=default_backend()
                     )
    key = base64.urlsafe_b64encode(kdf.derive(mem_pswd.encode("latin1")))   
    f = Fernet(key)
    return f.encrypt(secret.encode("latin1"))      
 
def decrypt(secret, mem_pswd,config_file = CONFIG_FILE):
    """Decrypts a secrets using a fixed key and a memorable password
    input:
    secret       encrypted secret
    mem_pswd     memorable password (unicode)
    config_file  a path to the configuration file containing the encrypted key
    output:
    The decrypted secret 
    """
    data = get_configuration(config_file)
    salt = data['key'].encode('latin1')
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=100000,
                     backend=default_backend()
                     )
    key = base64.urlsafe_b64encode(kdf.derive(mem_pswd.encode("latin1")))   
    f = Fernet(key)
    return f.decrypt(secret).decode("latin1")    