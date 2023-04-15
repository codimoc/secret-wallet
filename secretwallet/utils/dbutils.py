'''
Created on 24 Dec 2019

@author: codimoc
'''

from datetime import datetime
import sys

from secretwallet.constants import parameters, Secret
from secretwallet.utils.cryptutils import encrypt_key, decrypt, decrypt_info
from secretwallet.utils.logging import get_logger
from secretwallet.storage.aws_dynamo import AWSDynamoTable

import secretwallet.utils.ioutils as iou


logger = get_logger(__name__, parameters.get_log_level())
parameters.register_logger(__name__, logger)

SEPARATOR="#-#"

def secret_to_dictionary(secret:Secret, mem_pwd = None, salt = None, needs_decrypt:bool = True):
    ret = {'domain'    : secret.domain,
           'access'    : secret.access,
           'timestamp' : secret.timestamp}
    if needs_decrypt:
        ret['uid']  = decrypt(secret.user_id, mem_pwd, salt)
        ret['pwd']  = decrypt(secret.password, mem_pwd, salt)
        ret['info'] = decrypt_info(secret.info, mem_pwd, salt)
    else:
        ret['uid']  = secret.user_id
        ret['pwd']  = secret.password
        ret['info'] = secret.info
    return ret

def decrypt_secret(secret:Secret, mem_pwd:str, salt:str)->Secret:
    return Secret(domain = secret.domain,
                  access = secret.access,
                  user_id = decrypt(secret.user_id, mem_pwd, salt),
                  password = decrypt(secret.password, mem_pwd, salt),
                  info = decrypt_info(secret.info, mem_pwd, salt),
                  timestamp = secret.timestamp
                  )

def _get_table()->object:
    #we hard-code this to a AWS DynamoDB table for now
    #TODO: this will require a parameter to decide which storage type
    return AWSDynamoTable(parameters.get_table_name(), parameters.get_profile_name())

def _backup_table(backup_name:str)->object:
    return _get_table().backup_table(backup_name)

def _cleanup_table_backups(backup_name:str)->None:
    _get_table().cleanup_table_backups(backup_name)

def _drop_table():
    _get_table().drop_table()

def has_table(table_name:str)->bool:
    "Checks if the table exists"
    try:
        return _get_table().has_table(table_name)
    except Exception as e:
        iou.my_output(e)
        logger.error(e)
        sys.exit(1)


def create_table(table_name=parameters.get_table_name()):
    "Creates a table if it does not exist"
    try:
        _get_table().create_table(table_name)
    except Exception as e:
        logger.error(e)
    if has_table(table_name):
        logger.info(f"Table {table_name} has been created")
        iou.my_output(f"Table {table_name} has been created")


def insert_secret(domain, access, uid, pwd, info, mem_pwd, salt=None, timestamp = None):
    """Insert a secret access record in the cloud DB
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    uid        the user id for that access
    pwd        the password for that access
    info       a map of informations (not encryted)
    mem_pwd    memorable password to encrypt the secret
    salt       a string representation of the salt (optional)
    timestamp  the secret timestamp. If not passed it is calculated
    """
    if salt is None:
        salt = parameters.get_salt_key()
    if timestamp is None:
        timestamp = datetime.now().isoformat()
    if uid is None:
        uid = ""
    if pwd is None:
        pwd = ""
    if info is None:
        info = {}
    secret = Secret(domain = domain,
                    access = access,
                    user_id = uid,
                    password = pwd,
                    info = info)
    _get_table().insert_record(secret, mem_pwd, salt, timestamp)
    
def insert_encrypted_secret(domain, access, uid, pwd, info, timestamp = None):
    """Insert a secret access record in the cloud DB
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    uid        the encrypted user id for that access
    pwd        the encrypted password for that access
    info       a map of informations (encryted)
    timestamp  the secret timestamp. If not passed it is calculated
    """
    if timestamp is None:
        timestamp = datetime.now().isoformat()
    if uid is None:
        uid = ""
    if pwd is None:
        pwd = ""
    if info is None:
        info = {}
    secret = Secret(domain = domain,
                    access = access,
                    user_id = uid,
                    password = pwd,
                    info = info)
    _get_table().insert_encrypted_record(secret,timestamp)    

def update_secret(domain, access, uid, pwd, info_key, info_value, mem_pwd, salt=None):
    """Update a secret access record in the cloud DB
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    uid        the user id for that access
    pwd        the password for that access
    info_key   the key for an extra info
    info_value the value for an extra info
    mem_pwd    memorable password to encrypt the secret
    salt       a string representation of the salt (optional)
    """
    if salt is None:
        salt = parameters.get_salt_key()
    timestamp = datetime.now().isoformat()
    secret = Secret(domain = domain,
                    access = access,
                    user_id = uid,
                    password = pwd,
                    info_key = info_key,
                    info_value = info_value)    
    try:
        _get_table().update_record_single_info(secret, mem_pwd, salt, timestamp)
    except:
        pass #the condition failed but there should be no side effect

def update_secret_info_dictionary(domain, access, enc_info):
    """Update the info dictionary of a secret
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    enc_info   the new info dictionary (encrypted) to replace the old one
    """

    timestamp = datetime.now().isoformat()
    try:
        secret = Secret(domain = domain,
                        access = access,
                        encrypted_info = enc_info)
        _get_table().update_record_info_dictionary(secret, timestamp)
    except:
        pass #the condition failed but there should be no side effect


def rename_secret(domain, access, new_domain, new_access):
    """Rename the domain and access of a secret
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    new_domain the new value for the domain
    new_access the new value for the access
    """
    table = _get_table()
    filter_secret = Secret(domain = domain, access = access)
    old_secret = table.get_record(filter_secret)
    if old_secret is not None:
        try:
            new_secret = Secret(domain = new_domain,
                                access = new_access,
                                user_id = old_secret.user_id,
                                password = old_secret.password,
                                info = old_secret.info)
            table.insert_encrypted_record(new_secret, datetime.now().isoformat())
            table.delete_record(filter_secret)
        except Exception as e:
            iou.my_output(e)
    else:
        iou.my_output(f"Could not find secret ({domain},{access})")

def has_secret(domain, access):
    """Checks the existence of a secret
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    """
    filter_secret = Secret(domain = domain, access = access)
    secret = _get_table().get_record(filter_secret)
    return secret is not None

def delete_secret(domain, access):
    """Delete a secret by primary key.
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    """
    filter_secret = Secret(domain = domain, access = access)
    _get_table().delete_record(filter_secret)

def delete_secrets(secrets):
    """Deletes all secrets passed as list of (domain, access) pairs
    input:
    secrets    a list of secrets, as Secret objects
    """
    for s in secrets:
        delete_secret(s.domain, s.access)

def get_secret(domain, access, mem_pwd=None, salt=None, needs_decrypt=True):
    """Retrieves a secret by primary key
    input:
    domain          the domain, i.e. logical context, of the secret
    access          the secret sub-domain or access specification
    mem_pwd         memorable password to encrypt the secret
    salt            a string representation of the salt (optional)
    need_decrypt    a flag to indicate if decryption is required (default True)
    output:
    returns the decrypted secret as a dictionary
    """
    if salt is None:
        salt = parameters.get_salt_key()

    filter_secret = Secret(domain = domain, access = access)
    secret = _get_table().get_record(filter_secret)
    if needs_decrypt:
        return decrypt_secret(secret, mem_pwd, salt)
    else:
        return secret


def list_secrets(domain):
    """List all secrets by domain
    input:
    domain    the domain of the secrets. If null all records are returned
    output:
    a list of Secret objects
    """
    filter_secret = Secret(domain=domain)
    return _get_table().query_record(filter_secret)

def get_all_secrets(mem_pwd=None, as_dictionary=True, needs_decrypt = True):
    """Get all secrets and return them as a list of dictionaries or secret objects
    input:
    mem_pwd        the memorable password
    as_dictionary  a flag to select the type ot representation: dictionary or Secret
    needs_decrypt  a flag indicatinf that the returned secrets should be decrypted
    output:
    a list of secrets as dictionaries or secret objects depending on the flag passed
    """
    secrets = []
    for s in list_secrets(None):
        if as_dictionary:
            secret = get_secret(s.domain, s.access, mem_pwd, None, needs_decrypt) #decrypted
            secrets.append(secret_to_dictionary(secret, needs_decrypt=False))
        else:
            secrets.append(get_secret(s.domain, s.access, mem_pwd, None, needs_decrypt)) #decrypted
    return secrets

def query_secrets_by_field(domain_sub, access_sub):
    """Query all secrets with domain and access containing the domain or access substrings
    input:
    domain_sub  the substring to be looked for in the domain keys
    access_sub  the substring to be looked for in the access keys
    output:
    a list of Secret objects
    """
    secrets = list_secrets(None)
    filter_secrets = lambda s:(domain_sub is None or domain_sub.lower() in s.domain.lower())\
                               and\
                               (access_sub is None or access_sub.lower() in s.access.lower())
    return [s for s in secrets if filter_secrets(s)]

def query_secrets_by_pattern(pattern):
    """Query all secrets with domain or access containing the pattern substrings
    input:
    pattern  the substring to be looked for in the domain or access field
    output:
    a list of Secret objects
    """
    secrets = list_secrets(None)
    lpt = pattern.lower()
    filter_secrets = lambda s: pattern is None or lpt in s.domain.lower() or lpt in s.access.lower()

    return [s for s in secrets if filter_secrets(s)]

def reconf_memorable(secrets, old_mem, new_mem, backup=False):
    """Reconfigure all secrets changing the memorable password
    input:
    secrets    a list of Secret objects
    old_mem    old memorable password
    new_mem    new memorable password
    backup     a boolean flag to request a full baclup of the table
    output:
    the BackupArn of the table
    """
    arn = None
    ns = len(secrets)
    i = 0
    if backup:
        arn = _get_table().backup_table("backup")
    for s in secrets:
        i+=1
        domain = s.domain
        access = s.access
        try:
            message = f"[{i}/{ns}] - Reconfiguring the secret ({domain},{access})"
            logger.info(message)
            iou.my_output(message)
            secret = get_secret(domain, access, old_mem)
            insert_secret("I", f"{domain}{SEPARATOR}{access}", secret.user_id,  secret.password,  secret.info, new_mem)
            rename_secret(domain, access, "D", f"{domain}{SEPARATOR}{access}")
            rename_secret("I", f"{domain}{SEPARATOR}{access}", domain, access)
            delete_secret("D", f"{domain}{SEPARATOR}{access}")
        except Exception as e:
            logger.error(e)
            message = f"Could not reconfigure ({domain},{access})"
            iou.my_output(message)
            logger.error(message)
    return arn

def reconf_salt_key(secrets, old_mem, new_device_pwd, backup=False):
    """Reconfigure all secrets changing the memorable password
    input:
    secrets         a list of Secret objects
    old_mem         old memorable password
    new_device_pwd  the new device password
    backup          a boolean flag to request a full baclup of the table
    output:
    the BackupArn of the table
    """
    ekey = encrypt_key(new_device_pwd)
    ns = len(secrets)
    i = 0
    arn = None
    if backup:
        arn =_backup_table("backup")
    for s in secrets:
        i += 1
        domain = s.domain
        access = s.access
        try:
            message = f"[{i}/{ns}] - Reconfiguring the secret ({domain},{access})"
            logger.info(message)
            iou.my_output(message)
            secret = get_secret(domain, access, old_mem)
            insert_secret("I", f"{domain}{SEPARATOR}{access}", secret.user_id,  secret.password,  secret.info, old_mem, ekey)
            rename_secret(domain, access, "D", f"{domain}{SEPARATOR}{access}")
            rename_secret("I", f"{domain}{SEPARATOR}{access}", domain, access)
            delete_secret("D", f"{domain}{SEPARATOR}{access}")
        except Exception as e:
            logger.error(e)
            message = f"Could not reconfigure ({domain},{access})"
            iou.my_output(message)
            logger.error(message)

    return arn


def count_secrets():
    """Returns the total number of secrets"""
    filter_secret = Secret()
    return len(_get_table().query_record(filter_secret))


