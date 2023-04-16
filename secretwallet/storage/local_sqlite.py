from datetime import datetime

from ..constants import Secret
from .table import Table


"""
    Proxy class for a table on a local sqlite3 DB
    The methods can throw so the client (dbutils functions) need to capture them
"""
class LocalSqLiteTable(Table):
    
    def __init__(self, table_name):
        """
        Construct a sqlite table identified by a table name
        """
        self.table_name = table_name
                
    def get_table(self):
        return Table.get_table(self)


    def backup_table(self, backup_name:str):
        return Table.backup_table(self, backup_name)


    def cleanup_table_backups(self, backup_name:str):
        return Table.cleanup_table_backups(self, backup_name)


    def drop_table(self):
        return Table.drop_table(self)


    def has_table(self, table_name:str=None):
        return Table.has_table(self, table_name)


    def create_table(self, table_name:str=None):
        return Table.create_table(self, table_name)


    def insert_record(self, 
        secret:Secret, 
        mem_pwd:str, 
        salt:str, 
        timestamp:str=datetime.now().isoformat()):
        return Table.insert_record(self, secret, mem_pwd, salt, timestamp)


    def insert_encrypted_record(self, 
        secret:Secret, 
        timestamp:str=datetime.now().isoformat()):
        return Table.insert_encrypted_record(self, secret, timestamp)


    def get_record(self, secret:Secret):
        return Table.get_record(self, secret)


    def update_record_single_info(self, 
        secret:Secret, 
        mem_pwd:str, 
        salt:str, 
        timestamp:str=datetime.now().isoformat()):
        return Table.update_record_single_info(self, secret, mem_pwd, salt, timestamp)


    def update_record_info_dictionary(self, 
        secret:Secret, 
        timestamp:str=datetime.now().isoformat()):
        return Table.update_record_info_dictionary(self, secret, timestamp)


    def delete_record(self, secret:Secret):
        return Table.delete_record(self, secret)


    def query_record(self, secret:Secret):
        return Table.query_record(self, secret)

