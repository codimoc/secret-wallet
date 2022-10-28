from contextlib import redirect_stdout
import io
import json
from multiprocessing import Process
import os
import sys
from time import sleep

import pytest
from secretwallet.constants import parameters
from secretwallet.main.myparser import Parser
from secretwallet.session.client import is_connected, stop_service
from secretwallet.session.service import my_session

import secretwallet.utils.cryptutils as cu
import secretwallet.utils.dbutils as du
import secretwallet.utils.ioutils as iou


DOMAIN = 'test_domain'
ACCESS = 'test_access'
UID    = 'me@HOME'
PWD    = 'pass'
INFO   = {'key':'value'}
MEM    = 'memorable'
LIFETIME = 240
TIMEOUT = 60


old_input = iou.my_input
old_output = iou.my_output
old_getpass = iou.my_getpass


@pytest.fixture
def cli_test_set_up():
    #mocking the user input
    iou.my_input  = lambda _:'yes'
    iou.my_output = lambda message, with_exit=False, with_logging=False: print(message)

    if is_connected():
        stop_service()
    p =Process(target=my_session, args =(MEM, LIFETIME, TIMEOUT))
    p.start()
    while not is_connected():
        pass

    du.insert_secret(DOMAIN, ACCESS, UID, PWD, INFO, MEM)


    yield

    iou.my_input = old_input
    iou.my_output = old_output
    iou.my_getpass = old_getpass
    du.delete_secret(DOMAIN,ACCESS)

    if is_connected():
        stop_service()
    p.terminate()


@pytest.mark.integration
def test_help(cli_test_set_up):
    sys.argv=['secret_wallet','help']
    #output redirection to string
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert 'list of secretwallet commands' in buf.getvalue()


@pytest.mark.integration
def test_list(cli_test_set_up):
    sys.argv=['secret_wallet','list']
    #output redirection to string
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "<domain>" in buf.getvalue()

@pytest.mark.integration
def test_empty_list(cli_test_set_up):
    sys.argv=['secret_wallet','list','-d','xxx']
    #output redirection to string
    with io.StringIO() as buf, redirect_stdout(buf):
        try:
            Parser()
        except:
            assert False, "An empty list should not raise and exception when formatted"
        assert "****" in buf.getvalue()


@pytest.mark.integration
def test_list_domain(cli_test_set_up):
    sys.argv=['secret_wallet','list','-d',DOMAIN]
    #output redirection to string
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert ACCESS in buf.getvalue()


@pytest.mark.integration
def test_set_secret(cli_test_set_up):
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', 'test_access_2', '-u','x@y','-p','mamma']
    #output redirection to string
    try:
        with io.StringIO() as buf, redirect_stdout(buf):
            Parser()
            du.list_secrets(DOMAIN)
            assert 'test_access_2' in buf.getvalue()
    finally:
        du.delete_secret(DOMAIN,'test_access_2')

@pytest.mark.integration
def test_get_secret(cli_test_set_up):
    sys.argv=['secret_wallet','get','-d',DOMAIN, '-a', ACCESS]
    #output redirection to string
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert ACCESS in buf.getvalue()

@pytest.mark.integration
def test_update_info(cli_test_set_up):
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
def test_rename_secret(cli_test_set_up):
    new_domain = "new domain_01"
    new_access = "new_access_01"

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
def test_query_by_domain(cli_test_set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

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
def test_query_by_access(cli_test_set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

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
def test_query_by_pattern(cli_test_set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

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
def test_qget_first_secret(cli_test_set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

    #when the list of secrete is returned they are ordered alphabetically
    #by domain, access. Hence the first secret is bella,pera, or the second record here
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
        assert "first record" in buf.getvalue() #get the inner value in the secret
        assert "second record" not in buf.getvalue()


@pytest.mark.integration
def test_qget_second_secret(cli_test_set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

    #when the list of secrete is returned they are ordered alphabetically
    #by domain, access. Hence the first secret is bella,pera, or the second record here
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
        assert "first record" not in buf.getvalue() #get the inner value in the secret
        assert "second record" in buf.getvalue()

@pytest.mark.integration
def test_qget_wrong_input(cli_test_set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

    #when the list of secrete is returned they are ordered alphabetically
    #by domain, access. Hence the first secret is bella,pera, or the second record here

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
        assert "first record" not in buf.getvalue() #get the inner value in the secret
        assert "second record" not in buf.getvalue()
        assert "I need a number"  in buf.getvalue()

@pytest.mark.integration
def test_delete_info_item(cli_test_set_up):
    domain = 'pera'
    access = "cotta"
    key1 = 'bella'
    value1 = 'pupa'
    key2 = 'toste'
    value2 = 'mele'

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
        assert "pupa" in buf.getvalue()
        assert "mele" in buf.getvalue()

    #now remove one item from the dictionary
    sys.argv=['secret_wallet','delete', '-d', domain, '-a', access, '-ik', key2]
    Parser()

    #check that the item is gone
    sys.argv=['secret_wallet','get', '-d', domain, '-a', access]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "pupa" in buf.getvalue()
        assert "mele" not in buf.getvalue()

@pytest.mark.integration
def test_rename_secret_no_new_values(cli_test_set_up):
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', ACCESS, '-ik','first_key','-iv','first_value']
    Parser()
    sys.argv=['secret_wallet','rename','-d',DOMAIN, '-a', ACCESS]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "No new keys have been passed" in buf.getvalue()

@pytest.mark.integration
def test_rename_secret_same_values(cli_test_set_up):
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', ACCESS, '-ik','first_key','-iv','first_value']
    Parser()
    sys.argv=['secret_wallet','rename','-d',DOMAIN, '-a', ACCESS, '-nd', DOMAIN, '-na', ACCESS]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "Both new values are the same as the originals: nothing to do" in buf.getvalue()

@pytest.mark.integration
def test_rename_secret_wrong_values(cli_test_set_up):
    sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', ACCESS, '-ik','first_key','-iv','first_value']
    Parser()
    sys.argv=['secret_wallet','rename','-d',DOMAIN, '-a', 'wrong', '-nd', DOMAIN, '-na', ACCESS]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "Could not find the secret to rename" in buf.getvalue()

@pytest.mark.integration
def test_conf_list(cli_test_set_up):
    sys.argv=['secret_wallet','conf','-l']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "secret wallet configuration is located" in buf.getvalue()

@pytest.mark.integration
def test_wrong_salt(cli_test_set_up):
    my_access = 'another'
    other_key = cu.encrypt_key('pirillo')
    du.insert_secret(DOMAIN, my_access, 'login', 'password', None, 'memorable', other_key)
    sleep(1)
    #the following shoud produce and InvalidToken error
    sys.argv=['secret_wallet','get','-d',DOMAIN, '-a', my_access]
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert 'InvalidToken' in buf.getvalue()

@pytest.mark.integration
def test_wrong_memorable_password(cli_test_set_up):
    my_access = 'another'
    try:
        #insert
        sys.argv=['secret_wallet','set','-d',DOMAIN, '-a', my_access, '-u','login','-p','password']
        Parser()
        #now change the memorable in the session
        sys.argv=['secret_wallet','client','-a','set','-v','azzo']
        Parser()
        sleep(1)
        #the following shoud produce and InvalidToken error
        sys.argv=['secret_wallet','get','-d',DOMAIN, '-a', my_access]
        with io.StringIO() as buf, redirect_stdout(buf):
            Parser()
            assert 'InvalidToken' in buf.getvalue()
    finally:
        du.delete_secret(DOMAIN,my_access)

@pytest.mark.integration
def test_shell_set_help(cli_test_set_up):
    #mocking input to pass a 'set -h' command in a shell
    iou.my_input = iou.MockableInput(['set -h','quit'])
    sys.argv=['secret_wallet','shell']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert 'usage: secret_wallet set' in buf.getvalue()

@pytest.mark.integration
def test_shell_set_get_delete(cli_test_set_up):
    password = 'Arz12@gh67!caz'
    #mocking password retrieval
    iou.my_getpass = lambda _: password
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

@pytest.mark.integration
def test_shell_set_rename_get_delete(cli_test_set_up):
    password = 'Arz12@gh67!caz'
    #mocking password retrieval
    iou.my_getpass = lambda _: password
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

@pytest.mark.integration
def test_dump(cli_test_set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

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

    sys.argv=['secret_wallet','dump']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "first record" in buf.getvalue() #get the inner value in the secret
        assert "second record" in buf.getvalue()

@pytest.mark.integration
def test_dump_to_file(cli_test_set_up):
    path = "test_dump_tp_file.txt"

    # first clean up the file if it exists
    if os.path.exists(path):
        os.remove(path)

    #the set the data
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

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

    #now do the test
    try:
        sys.argv=['secret_wallet','dump','-f', path]
        Parser()

        #now assert the file exists
        assert os.path.exists(path)

        #and that it contains the data
        with open(path) as f:
            data = f.read()
            assert "first record" in data
            assert "second record" in data

    finally:
        os.remove(path)

@pytest.mark.integration
def test_save(cli_test_set_up):
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

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

    sys.argv=['secret_wallet','save']
    with io.StringIO() as buf, redirect_stdout(buf):
        Parser()
        assert "first record" in buf.getvalue() #get the inner value in the secret
        assert "second record" in buf.getvalue()

@pytest.mark.integration
def test_save_to_file(cli_test_set_up):
    path = "test_dump_to_file.json"

    # first clean up the file if it exists
    if os.path.exists(path):
        os.remove(path)

    #the set the data
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

    #delete first
    du.delete_secret(domain1, access1)
    du.delete_secret(domain2, access2)
    #then set
    sys.argv=['secret_wallet','set','-d',domain1, '-a', access1, '-ik', 'idx', '-iv','first record']
    Parser()
    sys.argv=['secret_wallet','set','-d',domain2, '-a', access2, '-ik', 'idx', '-iv','second record']
    Parser()
    assert du.has_secret(domain1, access1)
    assert du.has_secret(domain2, access2)

    #now do the test
    try:
        sys.argv=['secret_wallet','save','-f', path]
        Parser()

        #now assert the file exists
        assert os.path.exists(path)

        #and that it contains the data
        with open(path) as f:
            data = json.load(f)
            first_record = [x for x in data if x["domain"]==domain1 and x["access"]==access1][0]
            second_record = [x for x in data if x["domain"]==domain2 and x["access"]==access2][0]
            assert "first record" == first_record["info"]["idx"]
            assert "second record" == second_record["info"]["idx"]

    finally:
        os.remove(path)

@pytest.mark.integration
def test_load_from_file(cli_test_set_up):
    path = "test_backup_file.json"

    # first clean up the file if it exists
    if os.path.exists(path):
        os.remove(path)

    #all the pre-existing secrets
    secrets = du.list_secrets(None)
    #clean-up
    du.delete_secrets(secrets)
    secrets = du.list_secrets(None)
    assert 0 == len(secrets)

    #now add some secrets

    #set the data
    domain1 = 'pera'
    access1 = "cotta"
    domain2 = 'bella'
    access2 = 'pera'

    #set the secrets
    sys.argv=['secret_wallet','set','-d',domain1, '-a', access1, '-ik', 'idx', '-iv','first record']
    Parser()
    sys.argv=['secret_wallet','set','-d',domain2, '-a', access2, '-ik', 'idx', '-iv','second record']
    Parser()

    #check the status now
    assert du.has_secret(domain1, access1)
    assert du.has_secret(domain2, access2)
    assert 2 == len(du.list_secrets(None)) #there should be two secrets
    s1a = du.get_secret(domain1, access1, MEM)
    s2a = du.get_secret(domain2, access2, MEM)

    #now save to a file
    try:
        sys.argv=['secret_wallet','save','-f', path]
        Parser()

        #now assert the file exists
        assert os.path.exists(path)

        #now clean-up the secrets again
        du.delete_secrets(du.list_secrets(None))
        assert 0 == len(du.list_secrets(None))

        #and reload from file
        sys.argv=['secret_wallet','load','-f', path]
        Parser()

        assert du.has_secret(domain1, access1)
        assert du.has_secret(domain2, access2)
        assert 2 == len(du.list_secrets(None)) #there should be two secrets  again
        s1b = du.get_secret(domain1, access1, MEM)
        s2b = du.get_secret(domain2, access2, MEM)
        assert s1a == s1b
        assert s2a == s2b

        #now try to reload the file without cleaning the table,
        #it should still work without side effects
        sys.argv=['secret_wallet','load','-f', path]
        Parser()

        assert du.has_secret(domain1, access1)
        assert du.has_secret(domain2, access2)
        assert 2 == len(du.list_secrets(None)) #there should be two secrets  again
        s1b = du.get_secret(domain1, access1, MEM)
        s2b = du.get_secret(domain2, access2, MEM)
        assert s1a == s1b
        assert s2a == s2b

    finally:
        os.remove(path)

