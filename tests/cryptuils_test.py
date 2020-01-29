'''
Created on 16 Dec 2019

@author: gualtiero
'''

import pytest
import os
import secretwallet.utils.cryptutils as cu 
from secretwallet.main.configuration import set_configuration, get_configuration
from secretwallet.utils.cryptutils import encrypt_key
from secretwallet.constants import parameters

@pytest.fixture
def set_up():
    path = os.path.dirname(__file__)
    conf_file = os.path.join(path,'data','.secretwallet','test.json')
    yield conf_file
    
    if os.path.exists(conf_file):
        os.remove(conf_file)
        os.rmdir(os.path.dirname(conf_file))
    parameters.clear()
    
        
def test_get_encrypted_key():
    passwd = u"passwd"
    ekey = cu.encrypt_key(passwd)
    assert ekey is not None 
    assert isinstance(ekey, str) 
    
    ekey2 = cu.encrypt_key(passwd)
    assert ekey2 == ekey    
            
def test_configure_save_key(set_up):
    conf_file = set_up
    passwd = u"passwd"
    set_configuration(encrypt_key(passwd), None, None, None, conf_file)
    
    data = get_configuration(conf_file)
    key = data['key'].encode('latin1')
    assert key is not None 
    assert isinstance(key, bytes)
    
def test_configure_save_many(set_up):
    conf_file = set_up
    passwd = u"passwd"
    profile = 'my profile'
    salt = 'my salt'
    table = 'my table'
    set_configuration(encrypt_key(passwd), profile, table, salt, conf_file)
    
    data = get_configuration(conf_file)
    key = data['key'].encode('latin1')
    assert key is not None 
    assert isinstance(key, bytes)
    assert profile == data['profile']
    assert salt == data['salt']
    assert table == data['table_name']    
    
def test_encrypt_decrypt_secret(set_up):
    conf_file = set_up
    c_pwd = u"passwd"
    m_pwd = u"memorabile"
    secret = u"mamma"
    set_configuration(encrypt_key(c_pwd), None, None, None, conf_file)
    parameters.set_data(get_configuration(conf_file))
    
    esecret = cu.encrypt(secret, m_pwd, parameters.get_salt_key())
    v1 = cu.decrypt(esecret, m_pwd, parameters.get_salt_key())
    esecret2 = cu.encrypt(secret, m_pwd, parameters.get_salt_key())
    v2 = cu.decrypt(esecret2, m_pwd, parameters.get_salt_key())
    assert v1 == v2
    assert v1 == secret
    
def test_encrypt_decrypt_no_config():
    c_pwd = u"passwd"
    m_pwd = u"memorabile"
    secret = u"mamma"
    key = cu.encrypt_key(c_pwd)    
    esecret = cu.encrypt(secret, m_pwd, key)
    v1 = cu.decrypt(esecret, m_pwd, key)
    esecret2 = cu.encrypt(secret, m_pwd, key)
    v2 = cu.decrypt(esecret2, m_pwd, key)
    assert v1 == v2
    assert v1 == secret        