'''
Created on 16 Dec 2019

@author: codimoc
'''

import pytest
import os
import secretwallet.utils.cryptutils as cu 

@pytest.fixture
def set_up():
    path = os.path.dirname(__file__)
    conf_file = os.path.join(path,'data','.secretwallet','test.json')
    yield conf_file
    
    if os.path.exists(conf_file):
        os.remove(conf_file)
        os.rmdir(os.path.dirname(conf_file))
    
def touch(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a'):
        os.utime(path, None)
        

def test_configure_config_already_there(set_up):
    conf_file = set_up
    #create the file
    touch(conf_file)
    with pytest.raises(RuntimeError, match="Found pre-existing"):
        cu.configure('passwd', conf_file)
        
def test_get_encrypted_key():
    passwd = b"passwd"
    ekey = cu._get_encripted_key(passwd)
    assert ekey is not None 
    assert isinstance(ekey, bytes) 
    
    ekey2 = cu._get_encripted_key(passwd)
    assert ekey2 == ekey    
            
def test_configure_save_key(set_up):
    conf_file = set_up
    passwd = u"passwd"
    cu.configure(passwd, conf_file)
    
    data = cu.get_configuration(conf_file)
    key = data['key'].encode('latin1')
    assert key is not None 
    assert isinstance(key, bytes)
    
def test_encrypt_decrypt_secret(set_up):
    conf_file = set_up
    c_pwd = u"passwd"
    m_pwd = u"memorabile"
    secret = u"mamma"
    cu.configure(c_pwd, conf_file)
    
    esecret = cu.encrypt(secret, m_pwd, conf_file)
    v1 = cu.decrypt(esecret, m_pwd, conf_file)
    esecret2 = cu.encrypt(secret, m_pwd, conf_file)
    v2 = cu.decrypt(esecret2, m_pwd, conf_file)
    assert v1 == v2
    assert v1 == secret
    
def test_encrypt_decrypt_no_config():
    c_pwd = u"passwd"
    m_pwd = u"memorabile"
    secret = u"mamma"
    key = cu._get_encripted_key(c_pwd.encode('latin1')).decode("latin1")    
    esecret = cu.encrypt(secret, m_pwd, salt=key)
    v1 = cu.decrypt(esecret, m_pwd, salt=key)
    esecret2 = cu.encrypt(secret, m_pwd, salt=key)
    v2 = cu.decrypt(esecret2, m_pwd, salt=key)
    assert v1 == v2
    assert v1 == secret        