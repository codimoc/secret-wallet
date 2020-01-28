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
    du.insert_secret(DOMAIN, ACCESS, UID, PWD, INFO, MEM, conf_file)
    
    p =Process(target=my_session, args =('memorable', 10, 5))
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
