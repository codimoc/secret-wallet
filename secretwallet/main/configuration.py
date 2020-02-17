import os
import json
import configparser
from secretwallet.constants import parameters, CONFIG_FILE, CREDENTIALS_FILE
from secretwallet.utils.fileutils import touch
from secretwallet.utils.cryptutils import encrypt_key
from secretwallet.utils.dbutils import create_table, has_table
from secretwallet.utils.password_manager import get_password

def has_configuration(config_file=CONFIG_FILE):
    """Checks if the configurations file CONFIG_FILE exists
    input:
    config_file    a path to the configuration file
    output:
    Boolean indicating if the configuration file exists"""
    return os.path.exists(config_file)

def has_credentials(credentials_file=CREDENTIALS_FILE):
    """Checks if the aws-credentials file CREDENIALS_FILE exists
    input:
    credentials_file   a path to the credentials file
    output:
    Boolean indicating if the configturation file exists"""
    return os.path.exists(credentials_file) 

def set_credentials(config_file, access_key, secret_access_key,region):
    """make or update credentials
    input:
    config_file       a path to the AWS configuration file
    access_key        the AWS access key
    secret_access_key the secret access key
    region            the AWS region
    """
    parser = configparser.ConfigParser()
    if has_credentials(config_file):
        parser.read(config_file)
    else:
        touch(config_file)        
    parser[parameters.get_profile_name()] = {'aws_access_key_id'    :  access_key,
                                             'aws_secret_access_key':  secret_access_key,
                                             'region'               :  region}

    with open(config_file, 'w') as f:
        parser.write(f)


def get_credentials(config_file=CREDENTIALS_FILE):
    """Retrieves AWS credentials
    input:
    config_file       a path to the AWS configuration file
    output:
    a dictionary with the AWS credentials
    """
    parser = configparser.ConfigParser()
    ret = {}
    if has_credentials(config_file):
        parser.read(config_file)
        ret = parser[parameters.get_profile_name()]
    return ret

def get_credentials_sections(config_file=CREDENTIALS_FILE):
    """Retrieves the AWS credentials sections
    input:
    config_file       a path to the AWS configuration file
    output:
    a list of AWS credentials sections
    """
    parser = configparser.ConfigParser()
    ret = []
    if has_credentials(config_file):
        parser.read(config_file)
        ret = parser.sections()
    return ret


def get_configuration(config_file = CONFIG_FILE):
    """Read the configuration file and returns it as a dictionary
    input:
    config_file    a path to the configuration file
    output:
    A data dictionary containing the configuration"""
    if not os.path.exists(config_file):
        raise FileNotFoundError("Missing configuration file: run the configuration script secret_wallet_conf")
    with open(config_file, 'r') as cfile:
        return json.load(cfile)
    
def list_configuration(config_file = CONFIG_FILE):
    """List the configuration parameters
    input:
    config_file    a path to the configuration file
    """
    conf = get_configuration(config_file)
    display_configuration(config_file, 'secret wallet configuration is located', conf)
    
def set_configuration_data(conf_data, conf_file = CONFIG_FILE):
    with open(conf_file, 'w') as cfile:
        json.dump(conf_data, cfile)    
    
def set_configuration(conf_key, profile = None, table = None, salt = None, config_file = CONFIG_FILE):
    """This writes the system configuration file with the specified overrides and the encrypted salt
       If the configuration file exists, this function returns an error message, since reconfiguing the salt
       requires changes to all the encripted information in the remote DB.
       If the configuration already exists it should raise an error
       input:
       conf_key        the encrypted configuration key
       profile          the override of the default profile (optionall)
       table            the override of the default table name  (optional)
       salt             the override of the default pre-salt string
       config_file      the configuration file, defaults to fixed location in CONFIG_FILE
       """
    if has_configuration(config_file) and has_table(table):
        raise RuntimeError("Found pre-existing configuration in %s. To reconfigure the secretes use the reconf command"%config_file)
    
    conf = {'key': conf_key}
    if profile is not None:
        conf['profile'] = profile
    if table is not None:
        conf['table_name'] = table
    if salt is not None:
        conf['salt'] = salt
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    set_configuration_data(conf, config_file)
    
def load_configurations(conf_file = CONFIG_FILE, credentials_file = CREDENTIALS_FILE):
    """
    Loads the configuration and aws credentials
    """
    try:
        if not has_credentials(credentials_file):
            raise FileNotFoundError("Missing configuration file: run the configuration script secret_wallet_conf")    
        
        if not has_configuration(conf_file):
            raise FileNotFoundError("Missing configuration file: run the configuration script secret_wallet_conf")
        parameters.set_data(get_configuration(conf_file))
    except Exception as e:
        print(e)
        exit(1)
        
def display_configuration(conf_file, content, conf):
    print(f"\nThe {content} at {conf_file}")
    for k,v in conf.items():
        print(f'{k:30} = {v:<40}')
        
        
def make_configurations():
    "Main configuration script"
    print("\nMain configuration script for your secret wallet.")
    print("Please press return to accept the pre-set values in square brackets, or type a new value:\n")
    
    answ = input("\nDo you want to configure the AWS credentials? (yes|skip) ")
    if answ.lower().startswith('y'):    
        profile           = input('{0:30}[{1:>30}] = '.format('AWS profile name',parameters.get_profile_name()))
        if len(profile) == 0:
            profile = parameters.get_profile_name()
        if has_credentials() and profile in get_credentials_sections():
            print('The AWS profile {0} is already in use. Choose another or reconfigure'.format(profile))
            exit(1)
        parameters.set_profile_name(profile)
        access_key        = input('{0:30}[{1:>30}] = '.format('AWS access key id',''))
        secret_access_key = input('{0:30}[{1:>30}] = '.format('AWS secret access key',''))
        region            = input('{0:30}[{1:>30}] = '.format('AWS region',''))
        cred = {'aws access key id'     : access_key,
                'aws seceret access key': secret_access_key,
                'aws region'            : region}
        
        display_configuration(CREDENTIALS_FILE, 'AWS credentials are located',cred)
        answ = input("\nDo you want to set the credentials? (yes|skip|exit) ")
        if answ.lower().startswith('y'):
            set_credentials(CREDENTIALS_FILE, access_key, secret_access_key, region)
        elif answ.lower().startswith('s'):
            pass
        else:
            exit(1)
        
    answ = input("\nDo you want to configure the the secret-wallet parameters? (yes|skip) ")
    if answ.lower().startswith('y'):
        profile           = input('{0:30}[{1:>30}] = '.format('AWS profile name',parameters.get_profile_name()))
        if len(profile) == 0:
            profile = parameters.get_profile_name()        
        table             = input('{0:30}[{1:>30}] = '.format('DynameDB table name',parameters.get_table_name()))
        if len(table) == 0:
            table = parameters.get_table_name()                
        if has_configuration() and has_table(table):
            
            print('The secret-wallet has been configured previously for the same table.\nTo protect secrets, you need to call a reconfigure procedure')
            exit(1)    
        conf_pwd = get_password('Configuration password', 6)
        conf_key = encrypt_key(conf_pwd)
            
        conf = {'configuration key': conf_key,
                'profile': profile,
                'table': table}
        parameters.set_profile_name(profile)
        parameters.set_table_name(table)
        display_configuration(CONFIG_FILE, 'secret wallet configuration is located', conf)     
        answ = input("\nDo you want to set the configuration parameters? (yes|exit) ")
        if answ.lower().startswith('y'):
            try:
                set_configuration(conf_key, profile, table, None, CONFIG_FILE)
                create_table(table)
            except Exception as e:
                print(e)
                print("Could not write the configuration file. Make sure you have AWS connection and try again")
        else:
            exit(1)    
    
    
