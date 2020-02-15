import pytest
from secretwallet.session.service import my_session
from secretwallet.session.client import get_session_password, set_session_password, stop_service, is_connected
from multiprocessing import Process
from time import sleep

@pytest.fixture
def set_up():
    lifetime = 6
    timeout = 3
    value = 'message'
    p =Process(target=my_session, args =(value, lifetime, timeout))
    p.start()
    
    yield
    
    p.join()

def test_get_password(set_up):
    sleep(1)
    assert 'message' == get_session_password()[1]
    
def test_set_password(set_up):
    sleep(1)
    res = get_session_password()
    assert 'fresh'   == res[0]
    assert 'message' == res[1]
    set_session_password('nuova')
    res = get_session_password()
    assert 'fresh'   == res[0]
    assert 'nuova' == res[1]
    
def test_expiry_password(set_up):
    sleep(1)
    res = get_session_password()
    assert 'fresh'   == res[0]
    assert 'message' == res[1]
    sleep(3)
    res = get_session_password()
    assert 'stale'   == res[0]
    assert res[1] is None
    
def test_connection_status(set_up):  
    sleep(1)
    assert is_connected()
    stop_service()
    assert not is_connected()
    
def test_lifetime(set_up): 
    sleep(7)
    assert not is_connected() 