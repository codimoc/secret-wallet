'''
Created on 13 Jan 2020

@author: codimoc
'''

import os
import pytest
import secretwallet.main.configuration as mc

@pytest.fixture
def set_up():
    path = os.path.dirname(__file__)
    conf_file = os.path.join(path,'data','.secretwallet','credentials')
    yield conf_file
    
    if os.path.exists(conf_file):
        os.remove(conf_file)
        os.rmdir(os.path.dirname(conf_file))
        

def test_no_aws_configuration(set_up):
    conf_file = set_up
    assert False == mc.has_credentials(conf_file)
    
def test_create_and_check_aws_configuration(set_up):
    conf_file = set_up
    access_key = '1234'
    secret_access_key = 'Abc4'
    region = 'my region'
    mc.set_credentials(conf_file, access_key, secret_access_key, region)
    assert True == mc.has_credentials(conf_file)
    credentials = mc.get_credentials(conf_file)
    assert access_key        == credentials.get('aws_access_key_id')
    assert secret_access_key == credentials.get('aws_secret_access_key')
    assert region            == credentials.get('region')
    
def test_change_and_check_aws_configuration(set_up):
    conf_file = set_up
    access_key = '1234'
    secret_access_key = 'Abc4'
    region = 'my region'
    mc.set_credentials(conf_file, access_key, secret_access_key, region)
    assert True == mc.has_credentials(conf_file)
    
    access_key = '456'
    secret_access_key = 'three cars'
    region = 'your region'
    mc.set_credentials(conf_file, access_key, secret_access_key, region)    
    credentials = mc.get_credentials(conf_file)
    assert access_key        == credentials.get('aws_access_key_id')
    assert secret_access_key == credentials.get('aws_secret_access_key')
    assert region            == credentials.get('region')    