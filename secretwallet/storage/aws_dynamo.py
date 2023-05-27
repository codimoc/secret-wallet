from datetime import datetime

import boto3
from boto3.dynamodb.conditions import Key

from ..constants import Secret
from ..utils.cryptutils import encrypt, encrypt_info
from .table import Table


MAX_REPEAT = 3
SUCCESS = 200

#some utility functions
def make_secret(d:dict)->Secret:
        return Secret(domain=d['domain'],
                      access=d['access'],
                      user_id = d['uid'],
                      password = d['pwd'],
                      info = d['info'],
                      timestamp = d['timestamp'])    

"""
    Proxy class for a table in a AWS DynamoDB database
    The methods can throw so the client (dbutils functions) need to capture them
"""
class AWSDynamoTable(Table):

    def __init__(self, table_name:str, profile_name:str):
        """
        Construct a table identified by a table name and a AWS profile_name
        """
        self.table_name = table_name
        self.profile_name = profile_name
        
    def get_table(self)->object:   
        session = boto3.session.Session(profile_name=self.profile_name)
        dynamodb = session.resource('dynamodb')
        return dynamodb.Table(self.table_name)
    
    def backup_table(self, backup_name:str):
        session = boto3.session.Session(profile_name=self.profile_name)
        client = session.client('dynamodb')
        res = client.create_backup(TableName = self.table_name, BackupName = backup_name)
        return res['BackupDetails']['BackupArn']

    def cleanup_table_backups(self, backup_name:str):
        session = boto3.session.Session(profile_name=self.profile_name)
        client = session.client('dynamodb')
        res = client.list_backups(TableName=self.table_name)
        for bkp in res['BackupSummaries']:
            if bkp['BackupName'] == backup_name:
                client.delete_backup(BackupArn=bkp['BackupArn'])

    def drop_table(self):
        session = boto3.session.Session(profile_name=self.profile_name)
        dynamodb = session.resource('dynamodb')
        dynamodb.Table(self.table_name).delete()
        
    def has_table(self, table_name:str=None)->bool:
        "Checks if the table exists"
        if table_name is None:
            table_name = self.table_name
        session = boto3.session.Session(profile_name=self.profile_name)
        dynamodb = session.resource('dynamodb')
        names = [x.table_name for x in dynamodb.tables.all()]
        return table_name in names
    
    def create_table(self, table_name:str=None):
        "Creates a table if it does not exist"
        if table_name is None:
            table_name = self.table_name        
        if self.has_table(table_name):
            return
        session = boto3.session.Session(profile_name=self.profile_name)
        dynamodb = session.resource('dynamodb')
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
        dynamodb.Table(self.table_name).wait_until_exists()
        
    def insert_record(self,
                      secret:Secret,
                      mem_pwd:str,
                      salt:str,
                      timestamp:str = datetime.now().isoformat()) -> None:
        "insert a record in the secrets table"
        rep = 0
        status = 0
        #if the insert did not work, repeat up to MAX_REPEAT times
        while status != SUCCESS and rep < MAX_REPEAT:
            resp = self.get_table().put_item(Item={'domain'    : secret.domain,
                                                   'access'    : secret.access,
                                                   'uid'       : encrypt(secret.user_id, mem_pwd, salt),
                                                   'pwd'       : encrypt(secret.password, mem_pwd, salt),
                                                   'info'      : encrypt_info(secret.info, mem_pwd, salt),
                                                   'timestamp' : timestamp})
            status = resp['ResponseMetadata']['HTTPStatusCode']
            rep +=1

    def insert_encrypted_record(self,
                                secret:Secret,
                                timestamp:str = datetime.now().isoformat()) -> None:
        "insert a pre-encrypted record in the secrets table"
        rep = 0
        status = 0
        #if the insert did not work, repeat up to MAX_REPEAT times
        while status != SUCCESS and rep < MAX_REPEAT:        
            resp = self.get_table().put_item(Item={'domain'    : secret.domain,
                                                   'access'    : secret.access,
                                                   'uid'       : secret.user_id,
                                                   'pwd'       : secret.password,
                                                   'info'      : secret.info,
                                                   'timestamp' : timestamp})
            status = resp['ResponseMetadata']['HTTPStatusCode']
            rep +=1            
        
    def get_record(self,
                   secret: Secret) -> Secret:
        "retrieves an encrypted record keyed by domain and access, as a dictionary"
        rep = 0
        status = 0
        #if the insert did not work, repeat up to MAX_REPEAT times
        while status != SUCCESS and rep < MAX_REPEAT:        
            resp = self.get_table().get_item(Key={'domain'  : secret.domain,
                                                  'access'  : secret.access})
            status = resp['ResponseMetadata']['HTTPStatusCode']
            rep +=1            
            if 'Item' in resp:
                return make_secret(resp['Item'])
        return None
        
    
    def update_record_single_info(self,
                                  secret:Secret,
                                  mem_pwd:str,
                                  salt:str,
                                  timestamp:str = datetime.now().isoformat()) -> None:
        "update a record in the secrets table, with a maximum of one extra info stored in the Secret record"
        
        # #domain is the simbolyc field name and maps table column 'domain' to id #domain
        expression_attributes = {'#domain':'domain',
                                 '#access':'access'}
        # :domain is the symbolic value to be used in expressions for domain
        expression_values = {':domain':secret.domain,
                             ':access':secret.access}
    
        update_expression = "SET"
        condition_expression = "#domain = :domain AND #access = :access"

        if secret.user_id is not None:
            expression_attributes.update({'#uid':'uid'})
            expression_values.update({':uid' : encrypt(secret.user_id, mem_pwd, salt)})
            update_expression += ' #uid = :uid,'
        if secret.password is not None:
            expression_attributes.update({'#pwd':'pwd'})
            expression_values.update({':pwd' : encrypt(secret.password, mem_pwd, salt)})
            update_expression += ' #pwd = :pwd,'
        if secret.info_key is not None and secret.info_value is not None:
            expression_attributes.update({'#info':'info','#key':secret.info_key})
            expression_values.update({':info':encrypt(secret.info_value, mem_pwd, salt)})
            update_expression += ' #info.#key = :info,'
            
        #if nothing to update then return
        if update_expression == 'SET':
            return
        #now add the timestamp
        expression_attributes.update({'#timestamp':'timestamp'})
        expression_values.update({':ts': timestamp})
        update_expression += ' #timestamp = :ts'

        rep = 0
        status = 0
        #if the insert did not work, repeat up to MAX_REPEAT times
        while status != SUCCESS and rep < MAX_REPEAT:
            resp = self.get_table().update_item(Key={"domain": secret.domain, "access": secret.access},
                                                ExpressionAttributeNames  = expression_attributes,
                                                ExpressionAttributeValues = expression_values,
                                                UpdateExpression          = update_expression,
                                                ConditionExpression       = condition_expression
                                                )
            status = resp['ResponseMetadata']['HTTPStatusCode']
            rep +=1
        
    def update_record_info_dictionary(self,
                                      secret: Secret,
                                      timestamp:str = datetime.now().isoformat()) -> None:
        "update the info dictionary for a record in the secrets table"
        
        einfo = secret.encrypted_info
        if einfo is None:
            return
        
        expression_attributes = {'#domain':'domain',
                                 '#access':'access',
                                 '#info': 'info',
                                 '#timestamp':'timestamp'}
        expression_values = {':domain':secret.domain,
                             ':access':secret.access,
                             ':info': einfo,
                             ':ts': timestamp}
        update_expression = "SET #info = :info, #timestamp = :ts"
        condition_expression = "#domain = :domain AND #access = :access"

        rep = 0
        status = 0
        #if the insert did not work, repeat up to MAX_REPEAT times
        while status != SUCCESS and rep < MAX_REPEAT:        
            resp = self.get_table().update_item(Key={"domain": secret.domain, "access": secret.access},
                                                ExpressionAttributeNames  = expression_attributes,
                                                ExpressionAttributeValues = expression_values,
                                                UpdateExpression          = update_expression,
                                                ConditionExpression       = condition_expression
                                                )
            status = resp['ResponseMetadata']['HTTPStatusCode']
            rep +=1
        
    def delete_record(self, secret:Secret) -> None:
        "delete a single record based on domain and access keys"
        rep =0
        status =0
        #if the insert did not work, repeat up to MAX_REPEAT times 
        while status != SUCCESS and rep < MAX_REPEAT:       
            resp = self.get_table().delete_item(Key={'domain'  : secret.domain,
                                                     'access'  : secret.access})
            status = resp['ResponseMetadata']['HTTPStatusCode']
            rep +=1
        
    def query_record(self, secret:Secret) -> list: 
        "return a list of secrets matching the domain key passed"
        
        secrets = []
        if secret.domain is not None:
            resp = self.get_table().query(KeyConditionExpression=Key('domain').eq(secret.domain))
        else:
            resp = self.get_table().scan()
        for i in resp['Items']:
            secrets.append(Secret(domain=i['domain'],access=i['access']))
        #sort the list
        secrets.sort(key=lambda x: x.domain+x.access)

        return secrets        
        
                      
        
