'''
Created on 24 Dec 2019

@author: codimoc
'''

import boto3
import sys
from boto3.dynamodb.conditions import Key
from datetime import datetime
from secretwallet.constants import parameters
from secretwallet.utils.cryptutils import encrypt, decrypt

def _get_table():
    #TODO: manage Session in a better way. The table resource should be stored in the Session
    session = boto3.session.Session(profile_name=parameters.get_profile_name())
    dynamodb = session.resource('dynamodb')
    return dynamodb.Table(parameters.get_table_name())

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
        #TODO: Log exception
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
    except Exception:
        #TODO: manage exception below
        pass
    if has_table(table_name):
        #TODO: add logging
        print(f"Table {table_name} has been created")
     

def insert_secret(domain, access, uid, pwd, info, mem_pwd, salt=None):
    """Insert a secret access record in the cloud DB
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    uid        the user id for that access
    pwd        the password for that access
    info       a map of informations (not encryted)
    mem_pwd    memorable password to encrypt the secret
    salt       a string representation of the salt (optional)
    """
    if salt is None:
        salt = parameters.get_salt_key()
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
    expression_attributes = {'#domain':'domain',
                             '#access':'access'}
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
    """Delete a secret by primary key.
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    """    
    _get_table().delete_item(Key={'domain'  : domain,
                                  'access'  : access})
    
def delete_secrets(secrets, table):
    """Deletes all secrets passed as list of (domain, access) pairs
    input:
    secrets    a list of secrets, as domain, asset pairs
    table      the remote table
    """
    for s in secrets:
        table.delete_item(s[0], s[1])
    
def get_secret(domain, access, mem_pwd, salt=None):
    """Retrieves a secret by primary key
    input:
    domain     the domain, i.e. logical context, of the secret
    access     the secret sub-domain or access specification
    mem_pwd    memorable password to encrypt the secret
    salt       a string representation of the salt (optional)
    output:
    returns the decrypted secret
    """
    if salt is None:
        salt = parameters.get_salt_key()
    
    resp = _get_table().get_item(Key={'domain'  :domain,
                                      'access'  : access})
    ret = resp['Item']
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
    return secrets
    
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
        
