import json
import os
from os.path import expanduser, exists


if 'HOME_DIR' in globals():
    HOME_FOLDER = eval('HOME_DIR')
else:
    HOME_FOLDER = expanduser("~")


CONFIG_FOLDER = f"{HOME_FOLDER}/.secretwallet"
CONFIG_FILE = f"{CONFIG_FOLDER}/secretwallet.json"
CREDENTIALS_FOLDER = f"{HOME_FOLDER}/.aws"
CREDENTIALS_FILE = f"{CREDENTIALS_FOLDER}/credentials"

PRE_SALT = b"Nel mezzo del cammin di nostra vita"

#dynamoDB variables
SECRET_ACCESS_TABLE='access_secrets'

#AWS configuration
AWS_PROFILE='secret-wallet'

#session parameters
SESSION_ADDRESS = ('localhost',6417)
SESSION_PWD = b'yooCani3'
SESSION_TIMEOUT  = 60  #number of second the mem password is kept fresh
SESSION_LIFETIME = 600 #lifetime in seconds of the entire session


#Password policy
PWD_ATTEMPTS = 6 #number of attempts to get a good password
PWD_LENGTH = 8 #at least 8 chars long
PWD_NUMBERS=1  #at least one number
PWD_SPECIAL=1  #at least one special char
PWD_UPPER = 1  #at least an upper case

LOG_FILE = f"{CONFIG_FOLDER}/secretwallet.log"
LOG_MAX_FILE_SIZE =  1000000 #1MB
LOG_BACKUP_COUNT  = 1        #number of rotated backup files that are retained

def is_posix()->bool:
    return os.name=='posix'

#an object to store configurable parameters

def singleton(cls):
    instances = {}
    def wrapper(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return wrapper

@singleton
class Parameters(object):
    
    def __init__(self):
        self.__data = dict()
    
    def set_data(self,data):
        self.__data = data
    
    def configure(self, conf_file):
        if not exists(conf_file):
            raise FileNotFoundError("Missing configuration file: run the init command")
        with open(conf_file, 'r') as cfile:
            self.set_data(json.load(cfile))
            
    def clear(self):
        self.__data = dict()
    
    def get_profile_name(self):
        if 'profile' in self.__data:
            return self.__data['profile']
        else:
            return AWS_PROFILE
    
    def set_profile_name(self, profile):
        self.__data['profile'] = profile
        
    def get_pre_salt(self):
        if 'pre_salt' in self.__data:
            return self.__data['pre_salt']
        else:
            return PRE_SALT
        
    def get_table_name(self):
        if 'table_name' in self.__data:
            return self.__data['table_name']
        else:
            return SECRET_ACCESS_TABLE 
        
    def set_table_name(self, table):
        self.__data['table_name'] = table
    
    def get_salt_key(self):
        if 'key' in self.__data:
            return self.__data['key']
        else:
            raise RuntimeError('The encrypted key for the salt was not found')
        
    def set_salt_key(self, key):
        self.__data['key'] = key
    
    def get_session_timeout(self):
        if 'session_timeout' in self.__data:
            return self.__data['session_timeout']
        else:
            return SESSION_TIMEOUT 
        
    def set_session_timeout(self, timeout):
        self.__data['session_timeout'] = timeout
        

    def get_session_lifetime(self):
        if 'session_lifetime' in self.__data:
            return self.__data['session_lifetime']
        else:
            return SESSION_LIFETIME 
                
    def set_session_lifetime(self, lifetime):
        self.__data['session_lifetime'] = lifetime
        
    def get_session_address(self):
        if 'session_address' in self.__data:
            return self.__data['session_address']
        else:
            return SESSION_ADDRESS
        
    def get_session_connection_password(self):
        if 'session_connection_password' in self.__data:
            return self.__data['session_connection_password']
        else:
            return SESSION_PWD                        


#single object        
parameters = Parameters()