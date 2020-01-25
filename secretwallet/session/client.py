from multiprocessing.connection import Client
from secretwallet.constants import parameters

def get_password():
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'get','password':None})
    r = conn.recv()
    conn.close()
    #TODO: add logging
    return r['status'],r['password']

def set_password(pwd):
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'set','password':pwd})
    r = conn.recv()
    conn.close()
    #TODO: add logging
    print(r)

def stop_service():
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'stop','password':None})
    r = conn.recv()
    conn.close()
    #TODO: add logging
    print(r)
    
def test_connection():
    try:
        get_password()
        return True
    except ConnectionRefusedError:
        return False
    