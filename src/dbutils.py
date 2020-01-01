'''
Created on 24 Dec 2019

@author: gualtiero
'''

import boto3
from boto3.dynamodb.conditions import Key
from constants import SECRET_ACCESS_TABLE, CONFIG_FILE
from datetime import datetime
import cryptutils as cu

def _get_table():
    dynamodb = boto3.resource('dynamodb')
    return dynamodb.Table(SECRET_ACCESS_TABLE)

def insert_secret_login(domain, access, uid, pwd, mem_pwd, conf_file = CONFIG_FILE, salt = None):
    """Insert a secret access record in the cloud DB
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    uid        the user id for that access
    pwd        the password for that access
    mem_pwd    memorable password to encrypt the secret
    conf_file  file containing the encrypted key
    salt       a string representation of the salt (optional)
    """
    timestamp = datetime.now().isoformat()
    _get_table().put_item(Item={'domain'    : domain,
                                'access'    : access,
                                'uid'       : cu.encrypt(uid, mem_pwd, conf_file, salt),
                                'pwd'       : cu.encrypt(pwd, mem_pwd, conf_file, salt),
                                'timestamp' : timestamp})
    
def insert_secret_info(domain, access, info, mem_pwd, conf_file = CONFIG_FILE, salt=None):
    """Insert a secret access record in the cloud DB
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    info       the information to be stored
    mem_pwd    memorable password to encrypt the secret
    conf_file  file containing the encrypted key
    salt       a string representation of the salt (optional)
    """
    timestamp = datetime.now().isoformat()
    _get_table().put_item(Item={'domain'    : domain,
                                'access'    : access,
                                'info'      : cu.encrypt(info, mem_pwd, conf_file, salt),
                                'timestamp' : timestamp})    
    
def delete_secret(domain, access):
    """Delete a secret by primary key
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    """    
    _get_table().delete_item(Key={'domain'  : domain,
                                  'access'  : access})
    
def get_secret(domain, access, mem_pwd, conf_file = CONFIG_FILE, salt=None):
    """Retrieves a secret by primary key
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    mem_pwd    memorable password to encrypt the secret
    conf_file  file containing the encrypted key
    salt       a string representation of the salt (optional)
    output:
    returns the decrypted secret, info or login
    """
    sec = get_secret_login(domain, access, mem_pwd, conf_file, salt)
    if sec is not None:
        return sec
    else:
        return get_secret_info(domain, access, mem_pwd, conf_file, salt)

def get_secret_login(domain, access, mem_pwd, conf_file = CONFIG_FILE, salt=None):
    """Retrieves a secret by primary key
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    mem_pwd    memorable password to encrypt the secret
    conf_file  file containing the encrypted key
    salt       a string representation of the salt (optional)
    output:
    returns the secret (uid & password) decrypted
    """
    resp = _get_table().get_item(Key={'domain'  :domain,
                                      'access'  : access})
    #Beware the type of resp['Item']['uid'] is Binary (boto3 type)
    #to convert to bytes, needs the .value attribute
    if 'uid' in resp['Item'] and 'pwd' in resp['Item']:
        resp['Item']['uid'] = cu.decrypt(resp['Item']['uid'].value, mem_pwd, conf_file, salt)
        resp['Item']['pwd'] = cu.decrypt(resp['Item']['pwd'].value, mem_pwd, conf_file, salt)
        return resp['Item']
    else:
        return None

def get_secret_info(domain, access, mem_pwd, conf_file = CONFIG_FILE, salt = None):
    """Retrieves a secret by primary key
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    mem_pwd    memorable password to encrypt the secret
    conf_file  file containing the encrypted key
    salt       a string representation of the salt (optional)
    output:
    returns the secret info decrypted
    """
    resp = _get_table().get_item(Key={'domain'  :domain,
                                      'access'  : access})
    #Beware the type of resp['Item']['info'] is Binary (boto3 type)
    #to convert to bytes, needs the .value attribute
    if 'info' in resp['Item']:
        resp['Item']['info'] = cu.decrypt(resp['Item']['info'].value, mem_pwd, conf_file, salt)
        return resp['Item']
    else:
        return None
    
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
    return secrets
    
def count_secrets():
    """Returns the total number of secrets"""
    return _get_table().scan(Select='COUNT')['Count']