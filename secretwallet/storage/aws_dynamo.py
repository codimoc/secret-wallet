import boto3
from boto3.dynamodb.conditions import Key
from ..utils.dbutils import Secret
from ..utils.cryptutils import encrypt, encrypt_info
from docker import secret_wallet

#some utility functions
def make_secret(d:dict)->Secret:
        return Secret(domain=d['domain'],
                      access=d['access'],
                      user_id = d['uid'],
                      password = d['pwd'],
                      info = d['info'])    

"""
    Proxy class for a table in a AWS DynamoDB database
    The methos can throw so the client (dbutils functions) need to capture them
"""
class AWSDynamoTable:

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
        
    def has_table(self)->bool:
        "Checks if the table exists"
        session = boto3.session.Session(profile_name=self.profile_name)
        dynamodb = session.resource('dynamodb')
        names = [x.table_name for x in dynamodb.tables.all()]
        return self.table_name in names
    
    def create_table(self):
        "Creates a table if it does not exist"
        if self.has_table():
            return
        session = boto3.session.Session(profile_name=self.profile_name)
        dynamodb = session.resource('dynamodb')
        dynamodb.create_table(
            TableName=f"{self.table_name}",
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
                      timestamp:str) -> None:
        "insert a record in the secrets table"
        self.get_table().put_item(Item={'domain'    : secret.domain,
                                        'access'    : secret.access,
                                        'uid'       : encrypt(secret.user_id, mem_pwd, salt),
                                        'pwd'       : encrypt(secret.password, mem_pwd, salt),
                                        'info'      : encrypt_info(secret.info, mem_pwd, salt),
                                        'timestamp' : timestamp})
        
    def get_record(self,
                   secret: Secret) -> Secret:
        "retrieves an encripted record keyed by domain and access, as a dictionary"
        resp = self.get_table().get_item(Key={'domain'  : secret.domain,
                                              'access'  : secret.access})
        if 'Item' in resp:
            return make_secret(resp['Item'])
        return None
        
    
    def update_record_single_info(self,
                                  secret:Secret,
                                  mem_pwd:str,
                                  salt:str,
                                  timestamp:str) -> None:
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

        self.get_table().update_item(Key={"domain": secret.domain, "access": secret.access},
                                     ExpressionAttributeNames  = expression_attributes,
                                     ExpressionAttributeValues = expression_values,
                                     UpdateExpression          = update_expression,
                                     ConditionExpression       = condition_expression
                                     )
        
    def update_record_info_dictionary(self,
                                      secret: Secret,
                                      mem_pwd:str,
                                      salt:str,
                                      timestamp:str) -> None:
        "update the info dictionary for a record in the secrets table"
        
        einfo = None
        if secret.encrypted_info is not None:
            einfo = secret.encrypted_info
        elif secret.info is not None:
            einfo = encrypt_info(secret.info, mem_pwd, salt)
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

        self.get_table().update_item(Key={"domain": secret.domain, "access": secret.access},
                                     ExpressionAttributeNames  = expression_attributes,
                                     ExpressionAttributeValues = expression_values,
                                     UpdateExpression          = update_expression,
                                     ConditionExpression       = condition_expression
                                     )
        
    def delete_record(self, secret:Secret) -> None:
        "delete a single record based on domain and access keys"
        self.get_table().delete_item(Key={'domain'  : secret.domain,
                                          'access'  : secret.access})
        
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
        
                      
        
