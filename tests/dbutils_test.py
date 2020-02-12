import pytest
import secretwallet.utils.cryptutils as cu
import secretwallet.utils.dbutils as du 
from secretwallet.constants import parameters
from build.lib.secretwallet.utils.dbutils import _get_table

@pytest.fixture
def set_up():
    c_pwd = u"passwd"
    table_name = "test" 
    key = cu.encrypt_key(c_pwd)
    parameters.set_salt_key(key)
    parameters.set_table_name(table_name)
    du.create_table(table_name)
    yield 
    
    parameters.clear()

def test_insert_delete_login(set_up):
    m_pwd = u"memorabile"
    secret_uid = u"me@home"
    secret_pwd = u"ciao mamma"
    domain = u"my_domain" 
    access = u"my_access"
    ns = du.count_secrets()    
    try:        
        du.insert_secret(domain, access, secret_uid, secret_pwd, None, m_pwd, parameters.get_salt_key())
        assert ns+1 == du.count_secrets()
    finally:
        du.delete_secret(domain, access)
        assert ns == du.count_secrets()
        
def test_insert_select_compare_login(set_up):
    m_pwd = u"memorabile"
    secret_uid = u"me@home"
    secret_pwd = u"ciao mamma"
    domain = u"my_domain" 
    access = u"my_access"
    try:        
        du.insert_secret(domain, access, secret_uid, secret_pwd, None, m_pwd, parameters.get_salt_key())
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        assert secret_uid == res['uid']
        assert secret_pwd == res['pwd']
    finally:
        du.delete_secret(domain, access)

@pytest.mark.integration        
def test_insert_select_compare_info(set_up):
    m_pwd = u"memorabile"
    secret_info = {'message':'secret'}
    domain = u"my_domain" 
    access = u"my_access"
    try:        
        du.insert_secret(domain, access, None, None, secret_info, m_pwd, parameters.get_salt_key())
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        assert secret_info['message'] == res['info']['message']
    finally:
        du.delete_secret(domain, access)        

@pytest.mark.integration        
def test_has_secret(set_up):
    m_pwd = u"memorabile"
    secret_uid = u"me@home"
    secret_pwd = u"ciao mamma"
    domain = u"my_domain" 
    access = u"my_access"    
    try:        
        du.insert_secret(domain, access, secret_uid, secret_pwd, None, m_pwd, parameters.get_salt_key())
        assert du.has_secret(domain, access)
    finally:
        du.delete_secret(domain, access)

@pytest.mark.integration        
def test_has_not_secret(set_up):
    m_pwd = u"memorabile"
    secret_uid = u"me@home"
    secret_pwd = u"ciao mamma"
    domain = u"my_domain" 
    access = u"my_access"    
    try:        
        du.insert_secret(domain, access, secret_uid, secret_pwd, None, m_pwd, parameters.get_salt_key())
        assert not du.has_secret('new_domain', access)
    finally:
        du.delete_secret(domain, access)

@pytest.mark.integration        
def test_update_secret_login(set_up):
    m_pwd = u"memorabile"
    secret_uid = u"me@home"
    secret_uid2 = u"me@office"
    secret_pwd = u"ciao mamma"
    domain = u"my_domain" 
    access = u"my_access"    
    try:        
        ns = du.count_secrets()
        du.insert_secret(domain, access, secret_uid, secret_pwd, None, m_pwd, parameters.get_salt_key())
        assert ns+1 == du.count_secrets()
        assert du.has_secret(domain, access)
        old_ts = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())['timestamp']
        
        du.update_secret(domain, access, secret_uid2, None, None, None, m_pwd, parameters.get_salt_key())
        
        assert ns+1 == du.count_secrets() #no change to the number of secrets
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        assert secret_uid2 == res['uid']
        assert secret_pwd == res['pwd'] 
        assert old_ts <  res['timestamp']            
    finally:
        du.delete_secret(domain, access)

@pytest.mark.integration        
def test_update_secret_info_change_value(set_up):
    m_pwd = u"memorabile"
    domain = u"my_domain" 
    access = u"my_access" 
    secret_info = {'message':'secret'}
    info_key = 'message'
    info_val = 'a new secret'   
    try:        
        du.insert_secret(domain, access, None, None, secret_info, m_pwd, parameters.get_salt_key())
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        old_ts = res['timestamp']
        assert 'secret' == res['info'][info_key]
        
        du.update_secret(domain, access, None, None, info_key, info_val, m_pwd, parameters.get_salt_key())
        
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        assert info_val == res['info'][info_key] 
        assert old_ts <  res['timestamp']            
    finally:
        du.delete_secret(domain, access)
        
@pytest.mark.integration        
def test_update_secret_info_insert_value(set_up):
    m_pwd = u"memorabile"
    domain = u"my_domain" 
    access = u"my_access" 
    secret_info = {'message':'secret'}
    info_key = 'a new message'
    info_val = 'a new secret'   
    try:        
        du.insert_secret(domain, access, None, None, secret_info, m_pwd, parameters.get_salt_key())
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        old_ts = res['timestamp']
        assert 1 == len(res['info'])
        
        du.update_secret(domain, access, None, None, info_key, info_val, m_pwd, parameters.get_salt_key())
        
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        assert 2 == len(res['info'])
        assert info_val == res['info'][info_key]
        assert 'secret' == res['info']['message'] 
        assert old_ts <  res['timestamp']            
    finally:
        du.delete_secret(domain, access)
        
@pytest.mark.integration        
def test_update_secret_info_change_password_and_a_value(set_up):
    m_pwd = u"memorabile"
    domain = u"my_domain" 
    access = u"my_access" 
    secret_uid = u"me@home"
    secret_pwd = u"ciao mamma"
    secret_pwd2 = u"another password"    
    secret_info = {'message':'secret'}
    info_key = 'message'
    info_val = 'a new secret'   
    try:        
        du.insert_secret(domain, access, secret_uid, secret_pwd, secret_info, m_pwd, parameters.get_salt_key())
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        old_ts = res['timestamp']
        assert 'secret' == res['info'][info_key]
        assert secret_pwd == res['pwd'] 
        
        du.update_secret(domain, access, None, secret_pwd2, info_key, info_val, m_pwd, parameters.get_salt_key())
        
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        assert info_val == res['info'][info_key] 
        assert secret_pwd2 == res['pwd']
        assert old_ts <  res['timestamp']            
    finally:
        du.delete_secret(domain, access)
        
@pytest.mark.integration        
def test_update_missing_secret_no_effect(set_up):
    m_pwd = u"memorabile"
    domain = u"my_domain" 
    access = u"my_access"
    access2 = u"my_second access" 
    secret_uid = u"me@home"
    secret_pwd = u"ciao mamma"
    secret_pwd2 = u"my second password"    
    secret_info = {'message':'secret'}
    try:
        ns = du.count_secrets()
        du.insert_secret(domain, access, secret_uid, secret_pwd, secret_info, m_pwd, parameters.get_salt_key())
        assert ns + 1 == du.count_secrets()
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        old_ts = res['timestamp']
        assert 'secret' == res['info']['message']
        assert secret_pwd == res['pwd']
        assert secret_uid ==  res['uid']
        
        du.update_secret(domain, access2, None, secret_pwd2, None, None, m_pwd, parameters.get_salt_key())
        
        assert ns + 1 == du.count_secrets()
        res = du.get_secret(domain, access, m_pwd, parameters.get_salt_key())
        assert old_ts ==  res['timestamp']            
    finally:
        du.delete_secret(domain, access)
        
@pytest.mark.integration        
def test_has_table(set_up):
    assert True  == du.has_table(parameters.get_table_name())
    assert False == du.has_table('new_table')
    
def test_encrypt_decrypt_info():
    c_pwd = u"passwd"
    m_pwd = u"memorabile"
    key = cu.encrypt_key(c_pwd)

    info={'first':'value_1','second':'value_2'}
    ien = du.encrypt_info(info, m_pwd, key)
    ide = du.decrypt_info(ien, m_pwd, key)
    for key in info:
        assert ide[key] == info[key]
    
def test_delete_secrets():
    c_pwd = u"passwd"
    m_pwd = u"memorabile"
    domain = u"my_domain"  
    info = {'message':'secret'}
    key = cu.encrypt_key(c_pwd)
    cnt = du.count_secrets()
    table = _get_table()
    for i in range(5):
        access = f"access_{i}"
        du.insert_secret(domain, access, None, None, info, m_pwd, key)
#     assert cnt+5 == du.count_secrets()
    # now get the secret back by domain
    secrets = du.list_secrets(domain)
    #delete them in block
    du.delete_secrets(secrets, table)    
    #check that they are gone
    assert cnt== du.count_secrets()
