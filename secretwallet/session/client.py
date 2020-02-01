from multiprocessing.connection import Client
from secretwallet.constants import parameters

def get_session_password():
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'get','password':None})
    r = conn.recv()
    conn.close()
    #TODO: add logging
    return r['status'],r['password']

def set_session_password(pwd):
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'set','password':pwd})
    r = conn.recv()
    conn.close()
    #TODO: replace with logging
    print(r['status'])

def stop_service():
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'stop','password':None})
    r = conn.recv()
    conn.close()
    #TODO: replace with logging
    print(r['status'])
    
def is_connected():
    try:
        get_session_password()
        return True
    except ConnectionRefusedError:
        return False
    