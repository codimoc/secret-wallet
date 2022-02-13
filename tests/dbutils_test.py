import cryptography
import pytest
from secretwallet.constants import parameters

import secretwallet.utils.cryptutils as cu
import secretwallet.utils.dbutils as du 


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
    
@pytest.fixture
def insert_records():
    m_pwd = 'memorable'
    du.insert_secret("d1", "a1", "u1", "p1", {"k1":"v1","k2":"v2"}, m_pwd)
    du.insert_secret("d1", "a2", "u2", "p2", {"k3":"v3"}, m_pwd)
    du.insert_secret("d2", "a3", "u3", "p3", {"k4":"v4"}, m_pwd)
    yield
    
    du.delete_secrets(du.list_secrets("d1"))
    du.delete_secrets(du.list_secrets("d2"))
        
@pytest.fixture
def cleanup_backups():
    pass
    yield
    
    du._cleanup_table_backups('backup')
    

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
        
def test_wrong_salt_key(set_up):
    c_pwd = 'pirillo'
    wrong_key = cu.encrypt_key(c_pwd)
    m_pwd = u"memorabile"
    domain = u"my_domain" 
    access = u"my_access"    
    secret_uid = u"me@home"
    secret_pwd = u"ciao mamma"
    try:        
        du.insert_secret(domain, access, secret_uid, secret_pwd, None, m_pwd, wrong_key)
        with pytest.raises(cryptography.fernet.InvalidToken):
            du.get_secret(domain, access, m_pwd)
    finally:
        du.delete_secret(domain, access)
        
def test_wrong_memorable(set_up):
    m_pwd = u"memorabile"
    domain = u"my_domain" 
    access = u"my_access"    
    secret_uid = u"me@home"
    secret_pwd = u"ciao mamma"
    try:        
        du.insert_secret(domain, access, secret_uid, secret_pwd, None, m_pwd)
        with pytest.raises(cryptography.fernet.InvalidToken):
            du.get_secret(domain, access, 'pirillo')
    finally:
        du.delete_secret(domain, access)                
        
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
def test_update_info_dict_remove_key(set_up):
    m_pwd = u"memorabile"
    domain = u"my_domain" 
    access = u"my_access" 
    secret_info = {'key1': 'value1',
                   'key2': 'value2'}
    salt = parameters.get_salt_key()
    try:
        ns = du.count_secrets()
        du.insert_secret(domain, access, None, None, secret_info, m_pwd, parameters.get_salt_key())
        assert ns + 1 == du.count_secrets()
        res = du.get_secret(domain, access, m_pwd, salt, False) #no decryption of secret
        old_ts = res['timestamp']
        info = res['info']
        assert 2 == len(info)
        
        del info['key2'] #remove one entry
        du.update_secret_info_dictionary(domain, access, info)
        res = du.get_secret(domain, access, m_pwd, salt)
        ts = res['timestamp']
        info = res['info']
        assert 1 == len(info)
        assert 'value1' == info['key1']
        assert ts != old_ts
        
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
    
def test_delete_secrets(set_up):
    m_pwd = u"memorabile"
    domain = u"my_domain"  
    info = {'message':'secret'}
    #cleanup
    du.delete_secrets(du.list_secrets(None))
    cnt = du.count_secrets()
    for i in range(5):
        access = f"access_{i}"
        du.insert_secret(domain, access, None, None, info, m_pwd, parameters.get_salt_key())
    assert cnt+5 == du.count_secrets()
    # now get the secret back by domain
    secrets = du.list_secrets(domain)
    #delete them in block
    du.delete_secrets(secrets)    
    #check that they are gone
    assert cnt== du.count_secrets()
    
    
def test_rename_secret(set_up):
    m_pwd = u"memorabile"
    domain = u"my_domain"
    access = u"my_access"
    new_domain = u"new_domain"
    new_access = u"new_access"      
    info = {'message':'secret'}
    try:
        #before
        assert not du.has_secret(domain, access)
        assert not du.has_secret(new_domain, new_access)
        #after insertion
        du.insert_secret(domain, access, None, None, info, m_pwd, parameters.get_salt_key())    
        assert du.has_secret(domain, access)
        assert not du.has_secret(new_domain, new_access)
        #after rename  
        du.rename_secret(domain, access, new_domain, new_access)
        assert not du.has_secret(domain, access)
        assert du.has_secret(new_domain, new_access)
        res = du.get_secret(new_domain, new_access, m_pwd, parameters.get_salt_key())
        assert info['message'] == res['info']['message']
    finally:
        du.delete_secret(domain, access)
        du.delete_secret(new_domain, new_access)
        
def test_reconf_memorable(set_up, insert_records):
    old_mem = "memorable"
    new_mem = 'another'
    secrets = du.list_secrets("d1") + du.list_secrets("d2")
    assert 3 == len(secrets)
    sec = du.get_secret('d1', 'a1', old_mem)
    assert "v1" == sec['info']['k1']
    
    du.reconf_memorable(secrets, old_mem, new_mem)
    secrets = du.list_secrets("d1") + du.list_secrets("d2")        
    assert 3 == len(secrets)
    secrets = du.list_secrets("I") + du.list_secrets("D")
    assert 0 == len(secrets)
    sec = du.get_secret('d1', 'a1', new_mem)
    assert "v1" == sec['info']['k1']
    
    with pytest.raises(cryptography.fernet.InvalidToken):
        du.get_secret('d1', 'a1', old_mem)
            
def test_reconf_memorable_with_backup(set_up, insert_records, cleanup_backups):
    old_mem = "memorable"
    new_mem = 'another'
    secrets = du.list_secrets("d1") + du.list_secrets("d2")
    assert 3 == len(secrets)
    arn = du.reconf_memorable(secrets, old_mem, new_mem, True)
    assert arn is not None
        
def test_reconf_salt_key(set_up, insert_records):
    old_mem = "memorable"
    c_pwd = 'carpiato'
    new_salt_key = cu.encrypt_key(c_pwd)
    secrets = du.list_secrets("d1") + du.list_secrets("d2")
    assert 3 == len(secrets)
    sec = du.get_secret('d1', 'a1', old_mem)
    assert "v1" == sec['info']['k1']
    
    du.reconf_salt_key(secrets, old_mem, c_pwd, False)
    secrets = du.list_secrets("d1") + du.list_secrets("d2")        
    assert 3 == len(secrets)
    secrets = du.list_secrets("I") + du.list_secrets("D")
    assert 0 == len(secrets)
    sec = du.get_secret('d1', 'a1', old_mem, new_salt_key)
    assert "v1" == sec['info']['k1']
    
    with pytest.raises(cryptography.fernet.InvalidToken):
        du.get_secret('d1', 'a1', old_mem)
            
def test_query_records(set_up, insert_records):
    #test with no filter
    ns = du.count_secrets()
    secrets = du.query_secrets_by_field(None, None)
    assert ns == len(secrets)
    
    #test filter on domain with a d   
    secrets = du.query_secrets_by_field("d", None)
    assert 3 == len(secrets)
    
    #tets filter on domain with a 1
    secrets = du.query_secrets_by_field("1", None)
    assert 2 == len(secrets)
    
    #test filter domain with an x
    secrets = du.query_secrets_by_field("x", None)
    assert 0 == len(secrets)
    
    #test filter on access with a 1 in it
    secrets = du.query_secrets_by_field(None, "1")
    assert 1 == len(secrets)
    
    #test on both
    secrets = du.query_secrets_by_field("1", "2")
    assert 1 == len(secrets)
    
def test_get_all_secrets(set_up, insert_records):
    secrets = du.get_all_secrets('memorable')
    assert 3 == len(secrets)
    assert 'd1' == secrets[0]['domain']
    assert 'a1' == secrets[0]['access']
    assert 'u1' == secrets[0]['uid']
    assert 'p1' == secrets[0]['pwd']
    assert 'v1' == secrets[0]['info']['k1']
    assert 'v2' == secrets[0]['info']['k2']
    assert 'd1' == secrets[1]['domain']
    assert 'a2' == secrets[1]['access']
    assert 'u2' == secrets[1]['uid']
    assert 'p2' == secrets[1]['pwd']
    assert 'v3' == secrets[1]['info']['k3']
    assert 'd2' == secrets[2]['domain']
    assert 'a3' == secrets[2]['access']
    assert 'u3' == secrets[2]['uid']
    assert 'p3' == secrets[2]['pwd']
    assert 'v4' == secrets[2]['info']['k4']    
        
        