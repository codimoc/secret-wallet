from datetime import datetime

from ..constants import Secret, CONFIG_FOLDER
from .table import Table
from os import path, system
from ..utils import is_posix
import sqlite3
from ..utils.cryptutils import encrypt, encrypt_info
import json
from pickle import NONE


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
        self.db_path = path.join(CONFIG_FOLDER,'secretwallet.sqlite')

                
    def get_table(self):
        "This is not used in sqlite, i.e. we don't use a table object"
        return Table.get_table(self)


    def backup_table(self, backup_name:str):
        backup_db_path = path.join(CONFIG_FOLDER,backup_name,'.sqlite')
        if is_posix(): #on linux systems
            system(f'cp {self.db_path} {backup_db_path}')
        else: #windows
            system(f'copy {self.db_path} {backup_db_path}')
        return backup_db_path


    def cleanup_table_backups(self, backup_name:str):
        backup_db_path = path.join(CONFIG_FOLDER,backup_name,'.sqlite')
        if is_posix(): #on linux systems
            system(f'rm {backup_db_path}')
        else: #windows
            system(f'del {backup_db_path}')


    def drop_table(self):
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()
            cursor.execute("DROP TABLE IF EXISTS ?;", (self.table_name,))
        finally:
            cursor.close()
            connection.close


    def has_table(self, table_name:str=None):
        "Checks if the table exists"
        result = False
        if table_name is None:
            table_name = self.table_name        
        query = """SELECT count(1)
                   FROM sqlite_schema 
                   WHERE type='table' 
                   AND name= ?;"""        
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()
            cursor.execute(query,(table_name,))
            result = (cursor.fetchone()[0] == 1)
        finally:
            cursor.close()
            connection.close
        return result


    def create_table(self, table_name:str=None):
        "Creates a table if it does not exist"
        if table_name is None:
                table_name = self.table_name
        if self.has_table(table_name):
            return
        #todo: info field should be json        
        query = f"""CREATE TABLE IF NOT EXISTS [{self.table_name}] (
                      domain TEXT NOT NULL,
                      access TEXT NOT NULL,
                      uid TEXT,
                      pwd TEXT,
                      info TEXT, 
                      timestamp TEXT,
                      PRIMARY KEY (domain, access) );
                """
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()
            cursor.execute(query)
            connection.commit()
        finally:
            cursor.close()
            connection.close


    def insert_record(self, 
                     secret:Secret, 
                     mem_pwd:str, 
                     salt:str, 
                     timestamp:str=datetime.now().isoformat()):
        "insert a record in the secrets table"
        euid = encrypt(secret.user_id, mem_pwd, salt)
        epwd = encrypt(secret.password, mem_pwd, salt)
        einfo = json.dumps(encrypt_info(secret.info, mem_pwd, salt))
        
        record = (secret.domain,
                  secret.access,
                  euid,
                  epwd,
                  einfo,
                  timestamp)
        query = f"""INSERT INTO [{self.table_name}] 
                    VALUES (?1,?2,?3,?4,?5,?6) 
                    ON CONFLICT (domain, access)
                    DO UPDATE
                    SET uid = ?3,
                        pwd = ?4,
                        info = ?5,
                        timestamp = ?6;                    
                """
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()
            cursor.execute(query,record)
            connection.commit()
        finally:
            cursor.close()
            connection.close        


    def insert_encrypted_record(self, 
                                secret:Secret, 
                                timestamp:str=datetime.now().isoformat()):
        "insert a pre-encrypted record in the secrets table"        
        record = (secret.domain,
                  secret.access,
                  secret.user_id,
                  secret.password,
                  json.dumps(secret.info),
                  timestamp)
        query = f"""INSERT INTO [{self.table_name}] 
                    VALUES (?1,?2,?3,?4,?5,?6) 
                    ON CONFLICT (domain, access)
                    DO UPDATE
                    SET uid = ?3,
                        pwd = ?4,
                        info = ?5,
                        timestamp = ?6;                    
                """
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()
            cursor.execute(query,record)
            connection.commit()
        finally:
            cursor.close()
            connection.close


    def get_record(self, secret:Secret):
        "retrieves an encrypted record keyed by domain and access, as a dictionary"
        query = f"""SELECT * FROM [{self.table_name}]
                    WHERE domain = ?1
                    AND   access = ?2;
                """
        in_record = (secret.domain, secret.access)
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()
            cursor.execute(query,in_record)
            out_record = cursor.fetchone()
            if out_record is None:
                return None
            return Secret(domain=out_record[0],
                          access = out_record[1],
                          user_id = out_record[2],
                          password = out_record[3],
                          info = json.loads(out_record[4]),
                          timestamp = out_record[5])
        finally:
            cursor.close()
            connection.close


    def update_record_single_info(self, 
                                  secret:Secret, 
                                  mem_pwd:str, 
                                  salt:str, 
                                  timestamp:str=datetime.now().isoformat()) -> None:
        "update a record in the secrets table, with a maximum of one extra info stored in the Secret record"
        
        query = f"UPDATE [{self.table_name}]"
        params = { "domain" : secret.domain, "access" : secret.access, "timestamp" : timestamp}    
        condition = " WHERE domain=:domain AND access=:access;"
        change = False
        update = "SET timestamp = :timestamp"
        if secret.user_id is not None:
            change = True
            params["uid"] = encrypt(secret.user_id, mem_pwd, salt)
            update += ", uid = :uid"
        if secret.password is not None:
            change = True
            params["pwd"] = encrypt(secret.password, mem_pwd, salt)
            update += ", pwd = :pwd"
        if secret.info_key is not None and secret.info_value is not None:
            change = True
            old_secret = self.get_record(secret)
            if old_secret is not None:
                old_secret.info[secret.info_key] = encrypt(secret.info_value, mem_pwd, salt)
                params["info"] = json.dumps(old_secret.info)
                update += ", info = :info"
                
        if not change: #nothing to do
            return
        query += update + condition
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()
            cursor.execute(query,params)
            connection.commit()
        finally:
            cursor.close()
            connection.close        


    def update_record_info_dictionary(self, 
                                      secret:Secret, 
                                      timestamp:str=datetime.now().isoformat()) -> None:
        "update the info dictionary for a record in the secrets table (pre-encrypted)"
        einfo = secret.encrypted_info
        if einfo is None:
            return
        
        query = f"""UPDATE [{self.table_name}]
                    SET info =:info, timestamp=:timestamp
                    WHERE domain=:domain AND access=:access;
                """
        
        params = { "domain" : secret.domain, 
                   "access" : secret.access,
                   "info"   : json.dumps(einfo), 
                   "timestamp" : timestamp}
        
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()
            cursor.execute(query,params)
            connection.commit()
        finally:
            cursor.close()
            connection.close        


    def delete_record(self, secret:Secret)->None:
        "delete a single record based on domain and access keys"
        query = f"""DELETE from [{self.table_name}]
                    WHERE domain = ?1
                    AND access = ?2;"""
        in_record = (secret.domain, secret.access)
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()
            cursor.execute(query,in_record)
            connection.commit()
        finally:
            cursor.close()
            connection.close

    def query_record(self, secret:Secret)-> list:
        "return a list of secrets matching the domain key passed"
        where_clause = ""
        binding = False
        if secret.domain is not None:
            where_clause = "WHERE domain = ?"
            binding = True #there is a parameter to bind        
        query = f"""SELECT domain, access from [{self.table_name}] {where_clause};"""
        
        ret = list()
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()
            if binding:
                cursor.execute(query,(secret.domain,))
            else:
                cursor.execute(query)
            records = cursor.fetchall()
            for r in records:
                ret.append(Secret(domain=r[0], access=r[1]))
        finally:
            cursor.close()
            connection.close        
        
        return ret

