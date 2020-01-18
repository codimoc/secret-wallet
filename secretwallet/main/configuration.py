import os
import configparser
from secretwallet.constants import parameters, CONFIG_FILE, CREDENTIALS_FILE
from secretwallet.utils.fileutils import touch

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


def get_credentials(config_file):
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