import pytest
from secretwallet.constants import parameters, Secret
from secretwallet.utils.cryptutils import decrypt,decrypt_info, encrypt_info
import secretwallet.storage.aws_dynamo as ad

TEST_DOMAIN = u'test_domain'
TEST_ACCESS = u'test_access'
TEST_UID = u'test_uid'
TEST_PWD = u'test_pwd'
TEST_KEY = u'test_key'
TEST_VALUE = u'test_value'
TEST_MEM_PWD = u'test_memorable_password'

def make_test_secret(domain=TEST_DOMAIN,
                     access=TEST_ACCESS,
                     user_id=TEST_UID,
                     password=TEST_PWD,
                     info_key=TEST_KEY,
                     info_value=TEST_VALUE):
    info = {info_key: info_value}
    einfo = dict()
    return Secret(domain=domain,
                  access=access,
                  user_id=user_id,
                  password=password,
                  info_key=info_key,
                  info_value=info_value,
                  info = info,
                  encrypted_info = einfo)

@pytest.fixture
def set_up_table():
    table = ad.AWSDynamoTable(parameters.get_table_name(), parameters.get_profile_name())
    
    yield table
    
    #delete all secretes
    secrets = table.query_record(Secret())
    for s in secrets:
        table.delete_record(s)
    
def test_has_table(set_up_table):
    table = set_up_table #here i get the table from the set_up
    assert table.has_table()
    
def test_insert_and_get_secret(set_up_table):
    table = set_up_table    
    secret_in = make_test_secret()
    table.insert_record(secret_in, TEST_MEM_PWD, parameters.get_salt_key())
    secret_out = table.get_record(Secret(domain=TEST_DOMAIN,access=TEST_ACCESS))

    #tests
    assert TEST_DOMAIN == secret_out.domain
    assert TEST_ACCESS == secret_out.access
    assert TEST_UID == decrypt(secret_out.user_id,TEST_MEM_PWD,parameters.get_salt_key())
    assert TEST_PWD == decrypt(secret_out.password,TEST_MEM_PWD,parameters.get_salt_key())
    assert TEST_VALUE == decrypt(secret_out.info[TEST_KEY],TEST_MEM_PWD,parameters.get_salt_key())
    
def test_update_secret_single_info(set_up_table):
    table = set_up_table    
    secret_in = make_test_secret()
    table.insert_record(secret_in, TEST_MEM_PWD, parameters.get_salt_key())
    #now do some changes
    secret_in = make_test_secret(password=u'new password',info_value=u'new info value')
    table.update_record_single_info(secret_in, TEST_MEM_PWD, parameters.get_salt_key())
    #and extract the new secret 
    secret_out = table.get_record(Secret(domain=TEST_DOMAIN,access=TEST_ACCESS))
    
    #tests
    assert TEST_DOMAIN == secret_out.domain
    assert TEST_ACCESS == secret_out.access
    assert TEST_UID == decrypt(secret_out.user_id,TEST_MEM_PWD,parameters.get_salt_key())
    assert u'new password' == decrypt(secret_out.password,TEST_MEM_PWD,parameters.get_salt_key())
    assert u'new info value' == decrypt(secret_out.info[TEST_KEY],TEST_MEM_PWD,parameters.get_salt_key())
    
def test_update_secret_info_dictionary(set_up_table):
    table = set_up_table    
    secret_in = make_test_secret()
    table.insert_record(secret_in, TEST_MEM_PWD, parameters.get_salt_key())
    #now do some changes to the info dictionary
    info = dict()
    info["first key"] = u'first value'
    info["second key"] = u'second value'
    einfo = encrypt_info(info, TEST_MEM_PWD, parameters.get_salt_key())
    secret_in.encrypted_info.clear()
    secret_in.encrypted_info["first key"] = einfo["first key"]
    secret_in.encrypted_info["second key"] = einfo["second key"]
    table.update_record_info_dictionary(secret_in)
    #and extract the new secret 
    secret_out = table.get_record(Secret(domain=TEST_DOMAIN,access=TEST_ACCESS))
    #tests
    assert TEST_DOMAIN == secret_out.domain
    assert TEST_ACCESS == secret_out.access
    assert TEST_UID == decrypt(secret_out.user_id,TEST_MEM_PWD,parameters.get_salt_key())
    assert TEST_PWD == decrypt(secret_out.password,TEST_MEM_PWD,parameters.get_salt_key())
    dinfo = decrypt_info(secret_out.info, TEST_MEM_PWD, parameters.get_salt_key())
    dinfo["first key"] = u'first value'
    dinfo["second key"] = u'second value'
    
def test_query_secrets(set_up_table):
    table = set_up_table    
    secret1 = make_test_secret()
    table.insert_record(secret1, TEST_MEM_PWD, parameters.get_salt_key())
    secret2 = make_test_secret(domain=u'another domain')
    table.insert_record(secret2, TEST_MEM_PWD, parameters.get_salt_key())
        
    #tests
    secrets = table.query_record(Secret()) #an empty domain, should return all records
    assert 2 == len(secrets)
    
    filter_secret = make_test_secret() #only one secret with domain == TEST_DOMAIN
    secrets = table.query_record(filter_secret)    
    assert 1 == len(secrets)
        
    