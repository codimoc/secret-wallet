import json
from os.path import expanduser, exists
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

#single object        
parameters = Parameters()