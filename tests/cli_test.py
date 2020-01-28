import os
import sys
import io
from contextlib import redirect_stdout
import pytest
from secretwallet.constants import parameters
from secretwallet.main.configuration import get_configuration
from secretwallet.main.myparser import Parser
import secretwallet.utils.dbutils as du

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
    yield
    
    du.delete_secret(DOMAIN,ACCESS)
    parameters.clear()
    

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
