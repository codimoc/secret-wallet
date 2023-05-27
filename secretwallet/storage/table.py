from abc import ABC, abstractmethod
from ..constants import Secret

class Table(ABC):
    
    @abstractmethod
    def get_table(self)->object:
        "Returns the implementation of the DB table object"
        return self   
    
    @abstractmethod
    def backup_table(self, backup_name:str)->object:
        "Backs-up the table and returns an identifier of the backup"
        return None
    
    @abstractmethod
    def cleanup_table_backups(self, backup_name:str)->None:
        "Delete all table backups"
        pass

    @abstractmethod
    def drop_table(self)->None:
        "Drops the DB table"
        pass

    @abstractmethod
    def has_table(self, table_name:str=None)->bool:
        "Checks if the table exists"
        return False
    
    @abstractmethod
    def create_table(self, table_name:str=None)->None:
        "Creates a table if it does not exist"
        pass

    @abstractmethod
    def insert_record(self,
                      secret:Secret,
                      mem_pwd:str,
                      salt:str,
                      timestamp:str) -> None:
        "insert a record in the secrets table"
        pass

    @abstractmethod
    def insert_encrypted_record(self,
                                secret:Secret,
                                timestamp:str) -> None:
        "insert a pre-encrypted record in the secrets table"
        pass
    
    @abstractmethod
    def get_record(self,secret: Secret) -> Secret:
        "retrieves an encrypted record keyed by domain and access, as a dictionary"
        return None
        
    
    @abstractmethod
    def update_record_single_info(self,
                                  secret:Secret,
                                  mem_pwd:str,
                                  salt:str,
                                  timestamp:str) -> None:
        "update a record in the secrets table, with a maximum of one extra info stored in the Secret record"
        pass
    
    @abstractmethod
    def update_record_info_dictionary(self,
                                      secret: Secret,
                                      timestamp:str) -> None:
        "update the info dictionary for a record in the secrets table"
        pass
    
    @abstractmethod
    def delete_record(self, secret:Secret) -> None:
        "delete a single record based on domain and access keys"
        pass
    
    @abstractmethod
    def query_record(self, secret:Secret) -> list: 
        "return a list of secrets matching the domain key passed"
        return []
    
    