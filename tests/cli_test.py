import os
import sys
import io
from contextlib import redirect_stdout
import pytest
from secretwallet.constants import parameters
from secretwallet.main.configuration import get_configuration
from secretwallet.main.myparser import Parser
from secretwallet.session.service import my_session
from secretwallet.session.client import is_connected, stop_service
import secretwallet.utils.dbutils as du
import secretwallet.utils.cryptutils as cu
from multiprocessing import Process
from time import sleep

DOMAIN = 'test_domain'
ACCESS = 'test_access'
UID    = 'me@HOME'
PWD    = 'pass'
INFO   = {'key':'value'}
MEM    = 'memorable'


@pytest.fixture
def set_up():
    path = os.path.dirname(__file__)
    conf_file = os.path.join(path,'data','test_integration.json')
    parameters.set_data(get_configuration(conf_file)) 
    du.insert_secret(DOMAIN, ACCESS, UID, PWD, INFO, MEM)
    
    p =Process(target=my_session, args =('memorable', 60, 10))
    p.start()
       
    yield
    
    du.delete_secret(DOMAIN,ACCESS)
    parameters.clear()
    
    if is_connected():
        stop_service()
    p.terminate()    
    

@pytest.mark.integration
def test_help(set_up):
    sys.argv=['secret_wallet','help']
    #output redirection to string
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert 'list of secretwallet commands' in buf.getvalue()
    
 
@pytest.mark.integration
def test_list(set_up):
    sys.argv=['secret_wallet','list']
    #output redirection to string
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "<domain>" in buf.getvalue()


@pytest.mark.integration
def test_list_domain(set_up):
    sys.argv=['secret_wallet','list','-d',DOMAIN]
    #output redirection to string
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert ACCESS in buf.getvalue()


@pytest.mark.integration
def test_set_secret(set_up):
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', 'test_access_2', '-u','x@y','-p','mamma']
    #output redirection to string
    try:
        sleep(1)
        with io.StringIO() as buf, redirect_stdout(buf):
            Parser()
            du.list_secrets(DOMAIN)
            assert 'test_access_2' in buf.getvalue()
    finally:
        du.delete_secret(DOMAIN,'test_access_2')
        
@pytest.mark.integration
def test_get_secret(set_up):
    sys.argv=['secret_wallet','get','-d',DOMAIN, '-a', ACCESS]
    #output redirection to string
    sleep(1)
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert ACCESS in buf.getvalue()
        
@pytest.mark.integration        
def test_update_info(set_up):
    sleep(1)
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', ACCESS, '-ik','first_key','-iv','first_value']
    Parser()
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', ACCESS, '-ik','second_key','-iv','second_value']
    Parser()
    res = du.get_secret(DOMAIN, ACCESS, 'memorable', parameters.get_salt_key())
    assert 3 == len(res['info'])
    assert 'value' == res['info']['key']
    assert 'first_value' == res['info']['first_key']
    assert 'second_value' == res['info']['second_key']
    
def test_wrong_salt(set_up):
    my_access = 'another'
    other_key = cu.encrypt_key('azzo')
    sleep(1)
    #insert
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', my_access, '-u','login','-p','password']
    Parser()
    parameters.set_salt_key(other_key) #change the salt
    #the following shoud produce and InvalidToken error
    sys.argv=['secret_wallet','get','-d',DOMAIN, '-a', my_access]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert 'InvalidToken' in buf.getvalue()

def test_wrong_memorable_password(set_up):
    my_access = 'another'
    sleep(1)
    try:
        #insert
        sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', my_access, '-u','login','-p','password']
        Parser()
        #now change the memorable in the session
        sys.argv=['secret_wallet','client','-a','set','-v','azzo'] 
        Parser()
        #the following shoud produce and InvalidToken error
        sys.argv=['secret_wallet','get','-d',DOMAIN, '-a', my_access]
        with io.StringIO() as buf, redirect_stdout(buf):
            Parser()
            assert 'InvalidToken' in buf.getvalue()
    finally:
        du.delete_secret(DOMAIN,my_access)