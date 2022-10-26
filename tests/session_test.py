from multiprocessing import Process
from time import sleep

import pytest
from secretwallet.session.client import get_session_password, set_session_password, stop_service, is_connected, ping_session_server
from secretwallet.session.service import my_session


@pytest.fixture
def set_up():
    lifetime = 12
    timeout = 6
    value = 'message'

    #kill the listener
    if is_connected():
        stop_service()
    #now start the services
    p =Process(target=my_session, args =(value, lifetime, timeout))
    p.start()
    while not is_connected():
        pass

    yield

    p.terminate()


def test_get_password(set_up):
    assert 'message' == get_session_password()[1]

def test_set_password(set_up):
    res = get_session_password()
    assert 'fresh'   == res[0]
    assert 'message' == res[1]
    set_session_password('nuova')
    res = get_session_password()
    assert 'fresh'   == res[0]
    assert 'nuova' == res[1]

def test_expiry_password(set_up):
    res = get_session_password()
    assert 'fresh'   == res[0]
    assert 'message' == res[1]
    sleep(6)
    res = get_session_password()
    assert 'stale'   == res[0]
    assert res[1] is None

def test_connection_status(set_up):
    assert is_connected()
    stop_service()
    assert not is_connected()

def test_lifetime(set_up):
    assert is_connected()
    sleep(12)
    assert not is_connected()

def test_ping(set_up):
    assert "OK"==ping_session_server()
