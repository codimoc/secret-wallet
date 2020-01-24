from multiprocessing.connection import Client
from secretwallet.constants import SESSION_ADDRESS, SESSION_PWD

def get_password():
    conn = Client(SESSION_ADDRESS, authkey=SESSION_PWD)        
    conn.send({'action':'get','password':None})
    r = conn.recv()
    conn.close()
    #TODO: add logging
    return r['status'],r['password']

def set_password(pwd):
    conn = Client(SESSION_ADDRESS, authkey=SESSION_PWD)        
    conn.send({'action':'set','password':pwd})
    r = conn.recv()
    conn.close()
    #TODO: add logging

