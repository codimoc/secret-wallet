'''
Created on 24 Dec 2019

@author: codimoc
'''

from datetime import datetime
import sys

import boto3
from boto3.dynamodb.conditions import Key
from secretwallet.constants import parameters
from secretwallet.utils.cryptutils import encrypt, encrypt_key, decrypt
from secretwallet.utils.logging import get_logger

import secretwallet.utils.ioutils as iou


logger = get_logger(__name__, parameters.get_log_level())
parameters.register_logger(__name__, logger)

SEPARATOR="#-#"

def _get_table():
    #TODO: manage Session in a better way. The table resource should be stored in the Session
    session = boto3.session.Session(profile_name=parameters.get_profile_name())
    dynamodb = session.resource('dynamodb')
    return dynamodb.Table(parameters.get_table_name())

def _backup_table(backup_name):
    session = boto3.session.Session(profile_name=parameters.get_profile_name())
    client = session.client('dynamodb')
    res = client.create_backup(TableName = parameters.get_table_name(), BackupName = backup_name)
    return res['BackupDetails']['BackupArn']

def _cleanup_table_backups(backup_name):
    session = boto3.session.Session(profile_name=parameters.get_profile_name())
    client = session.client('dynamodb')
    res = client.list_backups(TableName=parameters.get_table_name())
    for bkp in res['BackupSummaries']:
        if bkp['BackupName'] == backup_name:
            client.delete_backup(BackupArn=bkp['BackupArn'])

def _drop_table(table_name):
    #TODO: manage Session in a better way. The table resource should be stored in the Session
    session = boto3.session.Session(profile_name=parameters.get_profile_name())
    dynamodb = session.resource('dynamodb')
    dynamodb.Table(table_name).delete()

def has_table(table_name):
    "Checks if the table exists"
    #TODO: manage Session in a better way. The table resource should be stored in the Session
    try:
        session = boto3.session.Session(profile_name=parameters.get_profile_name())
        dynamodb = session.resource('dynamodb')
        names = [x.table_name for x in dynamodb.tables.all()]
        return table_name in names
    except Exception as e:
        print(e)
        logger.error(e)
        sys.exit(1)


def create_table(table_name=parameters.get_table_name()):
    "Creates a table if it does not exist"
    if has_table(table_name):
        return
    session = boto3.session.Session(profile_name=parameters.get_profile_name())
    dynamodb = session.resource('dynamodb')
    try:
        dynamodb.create_table(
            TableName=f"{table_name}",
            # Declare your Primary Key in the KeySchema argument
            KeySchema=[
                {
                    "KeyType": "HASH",
                    "AttributeName": "domain"
                },
                {
                    "KeyType": "RANGE",
                    "AttributeName": "access"
                }
            ],

            # Any attributes used in KeySchema or Indexes must be declared in AttributeDefinitions
            AttributeDefinitions=[
                {
                    "AttributeName": "access",
                    "AttributeType": "S"
                },
                {
                    "AttributeName": "domain",
                    "AttributeType": "S"
                }
            ],
            # ProvisionedThroughput controls the amount of data you can read or write to DynamoDB per second.
            # You can control read and write capacity independently.
            ProvisionedThroughput={
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5
            },
        )
    except Exception as e:
        logger.error(e)
    if has_table(table_name):
        logger.info(f"Table {table_name} has been created")
        print(f"Table {table_name} has been created")


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
    _get_table().put_item(Item={'domain'    : domain,
                                'access'    : access,
                                'uid'       : encrypt(uid, mem_pwd, salt),
                                'pwd'       : encrypt(pwd, mem_pwd, salt),
                                'info'      : encrypt_info(info, mem_pwd, salt),
                                'timestamp' : timestamp})

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
    # #domain is the simbolyc field name and maps table column 'domain' to id #domain
    expression_attributes = {'#domain':'domain',
                             '#access':'access'}
    # :domain is the symbolic value to be used in expressions for domain
    expression_values = {':domain':domain,
                         ':access':access}
    update_expression = "SET"
    condition_expression = "#domain = :domain AND #access = :access"

    if uid is not None:
        expression_attributes.update({'#uid':'uid'})
        expression_values.update({':uid' : encrypt(uid, mem_pwd, salt)})
        update_expression += ' #uid = :uid,'
    if pwd is not None:
        expression_attributes.update({'#pwd':'pwd'})
        expression_values.update({':pwd' : encrypt(pwd, mem_pwd, salt)})
        update_expression += ' #pwd = :pwd,'
    if info_key is not None and info_value is not None:
        expression_attributes.update({'#info':'info','#key':info_key})
        expression_values.update({':info':encrypt(info_value, mem_pwd, salt)})
        update_expression += ' #info.#key = :info,'
    #if nothing to update then return
    if update_expression == 'SET':
        return
    #now add the timestamp
    expression_attributes.update({'#timestamp':'timestamp'})
    expression_values.update({':ts': timestamp})
    update_expression += ' #timestamp = :ts'

    try:
        _get_table().update_item(Key={"domain": domain, "access": access},
                                 ExpressionAttributeNames  = expression_attributes,
                                 ExpressionAttributeValues = expression_values,
                                 UpdateExpression          = update_expression,
                                 ConditionExpression       = condition_expression
                                 )
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
    expression_attributes = {'#domain':'domain',
                             '#access':'access',
                             '#info': 'info',
                             '#timestamp':'timestamp'}
    expression_values = {':domain':domain,
                         ':access':access,
                         ':info': enc_info,
                         ':ts': timestamp}
    update_expression = "SET #info = :info, #timestamp = :ts"
    condition_expression = "#domain = :domain AND #access = :access"

    try:
        _get_table().update_item(Key={"domain": domain, "access": access},
                                 ExpressionAttributeNames  = expression_attributes,
                                 ExpressionAttributeValues = expression_values,
                                 UpdateExpression          = update_expression,
                                 ConditionExpression       = condition_expression
                                 )
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
    resp = table.get_item(Key={'domain'  :domain,
                               'access'  : access})
    if 'Item' in resp and len(resp['Item'])>0:
        try:
            item = resp['Item']
            table.put_item(Item={'domain'    : new_domain,
                                 'access'    : new_access,
                                 'uid'       : item['uid'],
                                 'pwd'       : item['pwd'],
                                 'info'      : item['info'],
                                 'timestamp' : datetime.now().isoformat()})

            table.delete_item(Key={'domain'  : domain,
                                   'access'  : access})
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
    resp = _get_table().get_item(Key={'domain'  :domain,
                                      'access'  : access})
    return 'Item' in resp and len(resp['Item'])>0

def delete_secret(domain, access):
    """Delete a secret by primary key.
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    """
    _get_table().delete_item(Key={'domain'  : domain,
                                  'access'  : access})

def delete_secrets(secrets):
    """Deletes all secrets passed as list of (domain, access) pairs
    input:
    secrets    a list of secrets, as domain, asset pairs
    """
    for s in secrets:
        delete_secret(s[0], s[1])

def get_secret(domain, access, mem_pwd, salt=None, need_decrypt=True):
    """Retrieves a secret by primary key
    input:
    domain          the domain, i.e. logical context, of the secret
    access          the secret sub-domain or access specification
    mem_pwd         memorable password to encrypt the secret
    salt            a string representation of the salt (optional)
    need_decrypt    a flag to indicate if decryption is required (default True)
    output:
    returns the decrypted secret
    """
    if salt is None:
        salt = parameters.get_salt_key()

    resp = _get_table().get_item(Key={'domain'  :domain,
                                      'access'  : access})
    ret = resp['Item']
    if not need_decrypt:
        return ret

    if 'uid' in ret and ret['uid'] is not None and 'pwd' in ret and ret['pwd'] is not None:
        ret['uid'] = decrypt(ret['uid'], mem_pwd, salt)
        ret['pwd'] = decrypt(ret['pwd'], mem_pwd, salt)
    if 'info' in ret and ret['info'] is not None:
        ret['info'] = decrypt_info(ret['info'], mem_pwd, salt)
    return ret

def list_secrets(domain):
    """List all secrets by domain
    input:
    domain    the domain of the secrets. If null all records are returned
    output:
    a list of (domain, access) tuples
    """
    secrets = []
    if domain is not None:
        resp = _get_table().query(KeyConditionExpression=Key('domain').eq(domain))
    else:
        resp = _get_table().scan()
    for i in resp['Items']:
        secrets.append((i['domain'],i['access']))
    #sort the list
    secrets.sort(key=lambda x: x[0]+x[1])

    return secrets

def get_all_secrets(mem_pwd):
    """Get all secrets and return them as a list of disctionaries
    input:
    mem_pwd    the memorable password
    output:
    a list of secrets (each secret is a dictionary)
    """
    secrets = []
    for s in list_secrets(None):
        secrets.append(get_secret(s[0], s[1], mem_pwd))
    return secrets

def query_secrets_by_field(domain_sub, access_sub):
    """Query all secrets with domain and access containing the domain or access substrings
    input:
    domain_sub  the substring to be looked for in the domain keys
    access_sub  the substring to be looked for in the access keys
    output:
    a list of (domain, access) tuples
    """
    secrets = list_secrets(None)
    filter_secrets = lambda s:(domain_sub is None or domain_sub.lower() in s[0].lower())\
                               and\
                               (access_sub is None or access_sub.lower() in s[1].lower())
    return [s for s in secrets if filter_secrets(s)]

def query_secrets_by_pattern(pattern):
    """Query all secrets with domain or access containing the pattern substrings
    input:
    pattern  the substring to be looked for in the domain or access field
    output:
    a list of (domain, access) tuples
    """
    secrets = list_secrets(None)
    lpt = pattern.lower()
    filter_secrets = lambda s: pattern is None or lpt in s[0].lower() or lpt in s[1].lower()

    return [s for s in secrets if filter_secrets(s)]

def reconf_memorable(secrets, old_mem, new_mem, backup=False):
    """Reconfigure all secrets changing the memorable password
    input:
    secrets    a list of secrets, as domain, asset pairs
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
        arn =_backup_table("backup")
    for s in secrets:
        i+=1
        domain = s[0]
        access = s[1]
        try:
            message = f"[{i}/{ns}] - Reconfiguring the secret ({domain},{access})"
            logger.info(message)
            print(message)
            secret = get_secret(domain, access, old_mem)
            insert_secret("I", f"{domain}{SEPARATOR}{access}", secret['uid'],  secret['pwd'],  secret['info'], new_mem)
            rename_secret(domain, access, "D", f"{domain}{SEPARATOR}{access}")
            rename_secret("I", f"{domain}{SEPARATOR}{access}", domain, access)
            delete_secret("D", f"{domain}{SEPARATOR}{access}")
        except Exception as e:
            logger.error(e)
            message = f"Could not reconfigure ({domain},{access})"
            print(message)
            logger.error(message)
    return arn

def reconf_salt_key(secrets, old_mem, new_device_pwd, backup=False):
    """Reconfigure all secrets changing the memorable password
    input:
    secrets         a list of secrets, as domain, asset pairs
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
        domain = s[0]
        access = s[1]
        try:
            message = f"[{i}/{ns}] - Reconfiguring the secret ({domain},{access})"
            logger.info(message)
            print(message)
            secret = get_secret(domain, access, old_mem)
            insert_secret("I", f"{domain}{SEPARATOR}{access}", secret['uid'],  secret['pwd'],  secret['info'], old_mem, ekey)
            rename_secret(domain, access, "D", f"{domain}{SEPARATOR}{access}")
            rename_secret("I", f"{domain}{SEPARATOR}{access}", domain, access)
            delete_secret("D", f"{domain}{SEPARATOR}{access}")
        except Exception as e:
            logger.error(e)
            message = f"Could not reconfigure ({domain},{access})"
            print(message)
            logger.error(message)

    return arn


def count_secrets():
    """Returns the total number of secrets"""
    return _get_table().scan(Select='COUNT')['Count']

def encrypt_info(info,mem_pwd, salt):
    einfo = {}
    for key, value in info.items():
        einfo[key] = encrypt(value, mem_pwd, salt) #in string format
    return einfo

def decrypt_info(info, mem_pwd, salt):
    dinfo = {}
    for key, value in info.items():
        dinfo[key] = decrypt(value, mem_pwd, salt) #from string format
    return dinfo

