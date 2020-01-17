import json
import os
import pytest
from secretwallet.constants import parameters, Parameters, AWS_PROFILE, CONFIG_FILE, CREDENTIALS_FILE, SECRET_ACCESS_TABLE

@pytest.fixture
def set_up():
    path = os.path.dirname(__file__)
    conf_file = os.path.join(path,'data','.secretwallet','test.json')
    #overrides
    data_overrides = {'profile'            : 'my profile',
                      'config_folder'      : 'my config folder',
                      'config_file'        : 'my config file',
                      'credentials_folder' : 'my credentials folder',
                      'credentials_file'   : 'my credentials file',                      
                      'pre_salt'           : 'my salt',
                      'table_name'         : 'my table'}
    
    
    os.makedirs(os.path.dirname(conf_file), exist_ok=True)
    with open(conf_file, 'w') as cfile:
        json.dump(data_overrides, cfile)    
    yield conf_file
    
    parameters.clear()
    if os.path.exists(conf_file):
        os.remove(conf_file)
        os.rmdir(os.path.dirname(conf_file))
        
        
        
def test_parameters_singleton():
    assert parameters is not None
    assert AWS_PROFILE == parameters.get_profile_name()
    assert CONFIG_FILE == parameters.get_config_file()
    assert CREDENTIALS_FILE == parameters.get_credentials_file()
    assert SECRET_ACCESS_TABLE == parameters.get_table_name()
    assert parameters is Parameters() #singleton test
    
def test_parameters_overrides():
    data_overrides = {'profile'    : 'my profile',
                      'pre_salt'   : 'my salt',
                      'table_name' : 'my table'}
    parameters.set_data(data_overrides)
    assert data_overrides['profile']    == parameters.get_profile_name()
    assert data_overrides['pre_salt']   == parameters.get_pre_salt()
    assert data_overrides['table_name'] == parameters.get_table_name()
    
def test_parameters_configure(set_up):
    conf_file = set_up
    parameters.configure(conf_file)
    assert 'my profile'             == parameters.get_profile_name()
    assert 'my config folder'       == parameters.get_config_folder()
    assert 'my config file'         == parameters.get_config_file()
    assert 'my credentials folder'  == parameters.get_credentials_folder()
    assert 'my credentials file'    == parameters.get_credentials_file()    
    assert 'my salt'                == parameters.get_pre_salt()
    assert 'my table'               == parameters.get_table_name()    