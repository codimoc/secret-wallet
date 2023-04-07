import base64

from secretwallet.constants import parameters 
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt_key(config_password):
    """Produces an encripted and repeatible key
       combining the PRE_SALT string and a user password specific for 
       configuration generation
       input:
       config_password    a password used to make the unique configuration file (string repr)
       output:
       the encrypted key used for encrypting data (string repr)"""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=parameters.get_pre_salt(),
                     iterations=100000,
                     backend=default_backend()
                     )
    key = base64.urlsafe_b64encode(kdf.derive(config_password.encode("latin1")))
    return key.decode("latin1")
            
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
    
def encrypt(secret, mem_pswd, salt):
    """Encrypts a secretwallet using a fixed key and a memorable password
    input:
    secret       text to encrypt (unicode)
    mem_pswd     memorable password (unicode)
    salt         a string representation of the salt (optional)    
    output:
    The encrypted (byte string) value 
    """
    return _encrypt(secret, mem_pswd, salt).decode('latin1')

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
 
def decrypt(secret, mem_pswd, salt):
    """Decrypts a secretwallet using a fixed key and a memorable password
    input:
    secret       encrypted secret
    mem_pswd     memorable password (unicode)
    salt         a string representation of the salt (optional)    
    output:
    The decrypted secret 
    """
    return _decrypt(secret.encode('latin1'), mem_pswd, salt)

def encrypt_info(info,mem_pwd, salt):
    """Encrypts a a full dictionary of extra info
    input:
    info         a dictionary of extra information
    mem_pwd      memorable password (unicode)
    salt         a string representation of the salt (optional)    
    output:
    The encrypted dictionary of extra information 
    """
    einfo = {}
    if info is not None:
        for key, value in info.items():
            einfo[key] = encrypt(value, mem_pwd, salt) #in string format
    return einfo

def decrypt_info(info, mem_pwd, salt):
    """Decrypts a a full dictionary of extra info
    input:
    info         an encrypted dictionary of extra information
    mem_pwd      memorable password (unicode)
    salt         a string representation of the salt (optional)    
    output:
    The decrypted dictionary of extra information 
    """    
    dinfo = {}
    if info is not None:
        for key, value in info.items():
            dinfo[key] = decrypt(value, mem_pwd, salt) #from string format
    return dinfo
