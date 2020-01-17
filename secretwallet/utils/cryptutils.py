'''
Created on 15 Dec 2019

@author: gualtiero
'''

import os
import base64
import json

from secretwallet.constants import parameters
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
                     salt=parameters.get_pre_salt(),
                     iterations=100000,
                     backend=default_backend()
                     )
    key = base64.urlsafe_b64encode(kdf.derive(config_password))
    return key

def configure(config_password,config_file = parameters.get_config_file()):
    """This produce a static salt for cryptography. This salt is stored in the configuration file  on the client machine.
       If the configuration file exists, this function returns an error message, since reconfiguing the salt
       requires changes to all the encripted information in the remote DB
       input:
       config_password  the memorable password generating the salt
       config_file      the configuration file, defaults to fixed location in CONFIG_FILE
       """
    if _has_configuration(config_file):
        raise RuntimeError("Found pre-existing configuration in %s. To reconfigure the secretes use the reconf command"%config_file)
    
    ekey=_get_encripted_key(config_password.encode("latin1")).decode("latin1")
    conf = {'key': ekey}
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    with open(config_file, 'w') as cfile:
        json.dump(conf, cfile)
        
def get_configuration(config_file = parameters.get_config_file()):
    """Read the configuration file and returns it as a dictionary
    input:
    config_file    a path to the configuration file
    output:
    A data dictionary containing the configuration"""
    if not os.path.exists(config_file):
        raise FileNotFoundError("Missing configuration file: run the init command")
    with open(config_file, 'r') as cfile:
        return json.load(cfile)
    
def _encrypt(secret, mem_pswd, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt.encode('latin1'),
                     iterations=100000,
                     backend=default_backend()
                     )
    key = base64.urlsafe_b64encode(kdf.derive(mem_pswd.encode("latin1")))   
    f = Fernet(key)
    return f.encrypt(secret.encode("latin1"))
    
def encrypt(secret, mem_pswd, config_file = parameters.get_config_file(), salt = None):
    """Encrypts a secretwallet using a fixed key and a memorable password
    input:
    secret       text to encrypt (unicode)
    mem_pswd     memorable password (unicode)
    config_file  a path to the configuration file containing the encrypted key
    salt         a string representation of the salt (optional)    
    output:
    The encrypted (byte string) value 
    """
    if salt is None:
        salt = get_configuration(config_file)['key']
    return _encrypt(secret, mem_pswd, salt)

def _decrypt(secret, mem_pswd, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt.encode('latin1'),
                     iterations=100000,
                     backend=default_backend()
                     )
    key = base64.urlsafe_b64encode(kdf.derive(mem_pswd.encode("latin1")))   
    f = Fernet(key)
    return f.decrypt(secret).decode("latin1")    
 
def decrypt(secret, mem_pswd,config_file = parameters.get_config_file(), salt = None):
    """Decrypts a secretwallet using a fixed key and a memorable password
    input:
    secret       encrypted secret
    mem_pswd     memorable password (unicode)
    config_file  a path to the configuration file containing the encrypted key
    salt         a string representation of the salt (optional)    
    output:
    The decrypted secret 
    """
    if salt is None:
        salt = get_configuration(config_file)['key']
    return _decrypt(secret, mem_pswd, salt)    
