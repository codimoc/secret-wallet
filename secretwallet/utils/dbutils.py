'''
Created on 24 Dec 2019

@author: gualtiero
'''

import boto3
from boto3.dynamodb.conditions import Key
from datetime import datetime
from secretwallet.constants import parameters
from secretwallet.utils.cryptutils import encrypt, decrypt

def _get_table():
    session = boto3.session.Session(profile_name=parameters.get_profile_name())
    dynamodb = session.resource('dynamodb')
    return dynamodb.Table(parameters.get_table_name())

def insert_secret(domain, access, uid, pwd, info, mem_pwd, conf_file = parameters.get_config_file(), salt = None):
    """Insert a secret access record in the cloud DB
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    uid        the user id for that access
    pwd        the password for that access
    info       a map of informations (not encryted)
    mem_pwd    memorable password to encrypt the secret
    conf_file  file containing the encrypted key
    salt       a string representation of the salt (optional)
    """
    timestamp = datetime.now().isoformat()
    if uid is None:
        uid = ""
    if pwd is None:
        pwd = ""
    if info is None:
        info = {}
    _get_table().put_item(Item={'domain'    : domain,
                                'access'    : access,
                                'uid'       : encrypt(uid, mem_pwd, conf_file, salt),
                                'pwd'       : encrypt(pwd, mem_pwd, conf_file, salt),
                                'info'      : info,
                                'timestamp' : timestamp})
    
def update_secret(domain, access, uid, pwd, info_key, info_value, mem_pwd, conf_file = parameters.get_config_file(), salt = None):
    """Update a secret access record in the cloud DB
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    uid        the user id for that access
    pwd        the password for that access
    info_key   the key for an extra info
    info_value the value for an extra info
    mem_pwd    memorable password to encrypt the secret
    conf_file  file containing the encrypted key
    salt       a string representation of the salt (optional)
    """
    timestamp = datetime.now().isoformat()
    expression_attributes = {'#domain':'domain',
                             '#access':'access'}
    expression_values = {':domain':domain,
                         ':access':access}
    update_expression = "SET"
    condition_expression = "#domain = :domain AND #access = :access"
    
    if uid is not None:
        expression_attributes.update({'#uid':'uid'})
        expression_values.update({':uid' : encrypt(uid, mem_pwd, conf_file, salt)})
        update_expression += ' #uid = :uid,'
    if pwd is not None:
        expression_attributes.update({'#pwd':'pwd'})
        expression_values.update({':pwd' : encrypt(pwd, mem_pwd, conf_file, salt)})
        update_expression += ' #pwd = :pwd,'
    if info_key is not None and info_value is not None:
        expression_attributes.update({'#info':'info','#key':info_key})
        expression_values.update({':info':info_value})
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
        pass #the condition failed bu there should be no side effect
    
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
    """Delete a secret by primary key
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    """    
    _get_table().delete_item(Key={'domain'  : domain,
                                  'access'  : access})
    
def get_secret(domain, access, mem_pwd, conf_file = parameters.get_config_file(), salt=None):
    """Retrieves a secret by primary key
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    mem_pwd    memorable password to encrypt the secret
    conf_file  file containing the encrypted key
    salt       a string representation of the salt (optional)
    output:
    returns the decrypted secret
    """
    resp = _get_table().get_item(Key={'domain'  :domain,
                                      'access'  : access})
    #Beware the type of resp['Item']['uid'] is Binary (boto3 type)
    #to convert to bytes, needs the .value attribute
    ret = resp['Item']
    if 'uid' in ret and ret['uid'] is not None and 'pwd' in ret and ret['pwd'] is not None:
        ret['uid'] = decrypt(ret['uid'].value, mem_pwd, conf_file, salt)
        ret['pwd'] = decrypt(ret['pwd'].value, mem_pwd, conf_file, salt)
    return ret
    
def list_secrets(domain):
    """List all secretwallet by domain
    input:
    domain    the domain of the secretwallet. If null all records are returned
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
    """Returns the total number of secretwallet"""
    return _get_table().scan(Select='COUNT')['Count']