import os
import sys
import io
from contextlib import redirect_stdout
import pytest
from secretwallet.constants import parameters
from secretwallet.main.configuration import get_configuration, set_configuration_data
from secretwallet.main.myparser import Parser
import secretwallet.utils.ioutils as iou
from secretwallet.session.service import my_session
from secretwallet.session.client import is_connected, stop_service
import secretwallet.utils.cryptutils as cu
import secretwallet.utils.dbutils as du
from multiprocessing import Process
from time import sleep

DOMAIN = 'test_domain'
ACCESS = 'test_access'
UID    = 'me@HOME'
PWD    = 'pass'
INFO   = {'key':'value'}
MEM    = 'memorable'

   
old_input = iou.my_input
old_output = iou.my_output
old_getpass = iou.my_getpass
 

@pytest.fixture
def set_up():
    #mocking the user input
    iou.my_input  = lambda _:'yes'
    iou.my_output = lambda message,_=False: print(message)
    
    path = os.path.dirname(__file__)
    conf_file = os.path.join(path,'data','test_integration.json')
    conf_data = get_configuration(conf_file)
    parameters.set_data(conf_data) 
    du.insert_secret(DOMAIN, ACCESS, UID, PWD, INFO, MEM)
    
    p =Process(target=my_session, args =(MEM, 60, 10))
    p.start()
       
    yield conf_file
            
    iou.my_input = old_input
    iou.my_output = old_output
    iou.my_getpass = old_getpass
    du.delete_secret(DOMAIN,ACCESS)
    parameters.clear()
    set_configuration_data(conf_data, conf_file) 
    
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
def test_empty_list(set_up):
    sys.argv=['secret_wallet','list','-d','xxx']
    #output redirection to string
    with io.StringIO() as buf, redirect_stdout(buf):
        try:
            Parser()
        except:
            assert False, "An empty list should not raise and exception when formatted"
        assert "****" in buf.getvalue()        


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
    
@pytest.mark.integration        
def test_rename_secret(set_up):
    new_domain = "new domain_01"
    new_access = "new_access_01"
    
    sleep(1)
    #delete first
    du.delete_secret(DOMAIN, ACCESS)
    #then set   
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', ACCESS, '-ik','first_key','-iv','first_value']
    Parser()
    assert du.has_secret(DOMAIN, ACCESS)
    assert not du.has_secret(new_domain, new_access)
    
    #now rename
    sys.argv=['secret_wallet','rename','-d',DOMAIN, '-a', ACCESS, '-nd', new_domain,'-na', new_access]
    Parser()
    assert not du.has_secret(DOMAIN, ACCESS)
    assert du.has_secret(new_domain, new_access)
    du.delete_secret(new_domain, new_access)
    
@pytest.mark.integration
def test_query_by_domain(set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'
    
    sleep(1)
    #delete first
    du.delete_secret(domain1, access1)
    du.delete_secret(domain2, access2)
    #then set   
    sys.argv=['secret_wallet','set','-d',domain1, '-a', access1]
    Parser()
    sys.argv=['secret_wallet','set','-d',domain2, '-a', access2]
    Parser()
    assert du.has_secret(domain1, access1)
    assert du.has_secret(domain2, access2)
    
    #now querying by domain
    sys.argv=['secret_wallet','query','-d','pera']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "cotta" in buf.getvalue()
        assert "bella" not in buf.getvalue()
        
@pytest.mark.integration
def test_query_by_access(set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'
    
    sleep(1)
    #delete first
    du.delete_secret(domain1, access1)
    du.delete_secret(domain2, access2)
    #then set   
    sys.argv=['secret_wallet','set','-d',domain1, '-a', access1]
    Parser()
    sys.argv=['secret_wallet','set','-d',domain2, '-a', access2]
    Parser()
    assert du.has_secret(domain1, access1)
    assert du.has_secret(domain2, access2)
    
    #now querying by domain
    sys.argv=['secret_wallet','query','-a','pera']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "cotta" not in buf.getvalue()
        assert "bella" in buf.getvalue()
        
@pytest.mark.integration
def test_query_by_pattern(set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'
    
    sleep(1)
    #delete first
    du.delete_secret(domain1, access1)
    du.delete_secret(domain2, access2)
    #then set   
    sys.argv=['secret_wallet','set','-d',domain1, '-a', access1]
    Parser()
    sys.argv=['secret_wallet','set','-d',domain2, '-a', access2]
    Parser()
    assert du.has_secret(domain1, access1)
    assert du.has_secret(domain2, access2)
    
    #now querying by domain
    sys.argv=['secret_wallet','query','pera']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "cotta" in buf.getvalue()
        assert "bella" in buf.getvalue()
        
        
@pytest.mark.integration
def test_qget_first_secret(set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'
    
    #when the list of secrete is returned they are ordered alphabetically
    #by domain, access. Hence the first secret is bella,pera, or the second record here
    
    sleep(1)
    #delete first
    du.delete_secret(domain1, access1)
    du.delete_secret(domain2, access2)
    #then set   
    sys.argv=['secret_wallet','set','-d',domain1, '-a', access1, '-ik', 'idx', '-iv','second record']
    Parser()
    sys.argv=['secret_wallet','set','-d',domain2, '-a', access2, '-ik', 'idx', '-iv','first record']
    Parser()
    assert du.has_secret(domain1, access1)
    assert du.has_secret(domain2, access2)
    
    #now running a qget command with some mockable input
    iou.my_input = iou.MockableInput(["1"])    
    sys.argv=['secret_wallet','qget','pera']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        sleep(1)
        assert "first record" in buf.getvalue() #get the inner value in the secret 
        assert "second record" not in buf.getvalue()
        
        
@pytest.mark.integration
def test_qget_second_secret(set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'
    
    #when the list of secrete is returned they are ordered alphabetically
    #by domain, access. Hence the first secret is bella,pera, or the second record here
    
    sleep(1)
    #delete first
    du.delete_secret(domain1, access1)
    du.delete_secret(domain2, access2)
    #then set   
    sys.argv=['secret_wallet','set','-d',domain1, '-a', access1, '-ik', 'idx', '-iv','second record']
    Parser()
    sys.argv=['secret_wallet','set','-d',domain2, '-a', access2, '-ik', 'idx', '-iv','first record']
    Parser()
    assert du.has_secret(domain1, access1)
    assert du.has_secret(domain2, access2)
    
    #now running a qget command with some mockable input
    iou.my_input = iou.MockableInput(["2"])    
    sys.argv=['secret_wallet','qget','pera']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        sleep(1)
        assert "first record" not in buf.getvalue() #get the inner value in the secret 
        assert "second record" in buf.getvalue()
        
@pytest.mark.integration
def test_qget_wrong_input(set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'
    
    #when the list of secrete is returned they are ordered alphabetically
    #by domain, access. Hence the first secret is bella,pera, or the second record here
    
    sleep(1)
    #delete first
    du.delete_secret(domain1, access1)
    du.delete_secret(domain2, access2)
    #then set   
    sys.argv=['secret_wallet','set','-d',domain1, '-a', access1, '-ik', 'idx', '-iv','second record']
    Parser()
    sys.argv=['secret_wallet','set','-d',domain2, '-a', access2, '-ik', 'idx', '-iv','first record']
    Parser()
    assert du.has_secret(domain1, access1)
    assert du.has_secret(domain2, access2)
    
    #now running a qget command with some mockable input
    iou.my_input = iou.MockableInput(["string"])    
    sys.argv=['secret_wallet','qget','pera']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        sleep(1)
        assert "first record" not in buf.getvalue() #get the inner value in the secret 
        assert "second record" not in buf.getvalue()
        assert "I need a number"  in buf.getvalue()                     
        
@pytest.mark.integration
def test_delete_info_item(set_up):
    domain = 'pera'
    access = "cotta"
    key1 = 'bella'
    value1 = 'pupa'
    key2 = 'toste'
    value2 = 'mele'    
        
    sleep(1)
    #delete first
    du.delete_secret(domain, access)
    #then set   
    sys.argv=['secret_wallet','set','-d',domain, '-a', access, '-ik', key1, '-iv', value1]
    Parser()
    sys.argv=['secret_wallet','set','-d',domain, '-a', access, '-ik', key2, '-iv',value2]
    Parser()
    assert du.has_secret(domain, access)
        
    sys.argv=['secret_wallet','get', '-d', domain, '-a', access]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        sleep(1)
        assert "pupa" in buf.getvalue() 
        assert "mele" in buf.getvalue()
    
    #now remove one item from the dictionary    
    sys.argv=['secret_wallet','delete', '-d', domain, '-a', access, '-ik', key2]
    Parser()
    
    #check that the item is gone
    sys.argv=['secret_wallet','get', '-d', domain, '-a', access]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        sleep(1)
        assert "pupa" in buf.getvalue() 
        assert "mele" not in buf.getvalue()            
    
    
def test_rename_secret_no_new_values(set_up):
    sleep(1)
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', ACCESS, '-ik','first_key','-iv','first_value']
    Parser()
    sys.argv=['secret_wallet','rename','-d',DOMAIN, '-a', ACCESS]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "No new keys have been passed" in buf.getvalue()
        
def test_rename_secret_same_values(set_up):
    sleep(1)
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', ACCESS, '-ik','first_key','-iv','first_value']
    Parser()
    sys.argv=['secret_wallet','rename','-d',DOMAIN, '-a', ACCESS, '-nd', DOMAIN, '-na', ACCESS]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "Both new values are the same as the originals: nothing to do" in buf.getvalue()            
           
def test_rename_secret_wrong_values(set_up):
    sleep(1)
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', ACCESS, '-ik','first_key','-iv','first_value']
    Parser()
    sys.argv=['secret_wallet','rename','-d',DOMAIN, '-a', 'wrong', '-nd', DOMAIN, '-na', ACCESS]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "Could not find the secret to rename" in buf.getvalue() 
        
def test_conf_list(set_up):
    sys.argv=['secret_wallet','conf','-l']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "secret wallet configuration is located" in buf.getvalue()
        

def test_wrong_salt(set_up):
    my_access = 'another'
    other_key = cu.encrypt_key('pirillo')
    sleep(1)
    du.insert_secret(DOMAIN, my_access, 'login', 'password', None, 'memorable', other_key)
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

def test_shell_set_help(set_up):
    #mocking input to pass a 'set -h' command in a shell
    iou.my_input = iou.MockableInput(['set -h','quit'])
    sys.argv=['secret_wallet','shell']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert 'usage: secret_wallet set' in buf.getvalue()

def test_shell_set_get_delete(set_up):
    password = 'Arz12@gh67!caz'
    #mocking password retrieval
    iou.my_getpass = lambda question: password
    #mocking input to pass a 'set ...' command in a shell
    iou.my_input = iou.MockableInput(["set -d shell_test -a test -ik test -iv 'this is a test'",
                                      'get -d shell_test -a test',
                                      'delete -d shell_test -a test',
                                      'yes',
                                      'quit'])
    sys.argv=['secret_wallet','shell']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert 'this is a test' in buf.getvalue()

    #now check it is not there any longer
    assert not du.has_secret('shell_test','test')

def test_shell_set_rename_get_delete(set_up):
    password = 'Arz12@gh67!caz'
    #mocking password retrieval
    iou.my_getpass = lambda question: password
    #mocking input to pass a 'set ...' command in a shell
    iou.my_input = iou.MockableInput(["set -d shell_test -a test -ik test -iv 'this is a test'",
                                      'rename -d shell_test -a test -na test2',
                                      'yes',
                                      'get -d shell_test -a test2',
                                      'delete -d shell_test -a test2',
                                      'yes',
                                      'quit'])
    sys.argv=['secret_wallet','shell']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert 'this is a test' in buf.getvalue()

    #now check it is not there any longer
    assert not du.has_secret('shell_test','test')
    assert not du.has_secret('shell_test','test2')


