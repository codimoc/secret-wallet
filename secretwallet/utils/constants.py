'''
Created on 15 Dec 2019

@author: gualtiero
'''
from os.path import expanduser
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