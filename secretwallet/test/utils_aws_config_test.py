'''
Created on 13 Jan 2020

@author: codimoc
'''

import os
import pytest
import secretwallet.utils.aws_config as ac

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
    assert False == ac.has_credentials(conf_file)
    
def test_create_and_check_aws_configuration(set_up):
    conf_file = set_up
    access_key = '1234'
    secret_access_key = 'Abc4'
    region = 'my region'
    ac.set_credentials(conf_file, access_key, secret_access_key, region)
    assert True == ac.has_credentials(conf_file)
    credentials = ac.get_credentials(conf_file)
    assert access_key        == credentials.get('aws_access_key')
    assert secret_access_key == credentials.get('aws_secret_access_key')
    assert region            == credentials.get('region')