from multiprocessing.connection import Client
from secretwallet.constants import parameters
from secretwallet.utils.logging import get_logger

logger = get_logger(__name__)

def get_session_password():
    logger.info("Retrieving session password")
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'get','password':None})
    r = conn.recv()
    conn.close()
    return r['status'],r['password']

def set_session_password(pwd):
    logger.info("Setting session password")
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'set','password':pwd})
    r = conn.recv()
    conn.close()
    logger.debug(r['status'])

def stop_service():
    logger.info("Stopping the service")
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'stop','password':None})
    r = conn.recv()
    conn.close()
    logger.debug(r['status'])
    
def is_connected():
    try:
        get_session_password()
        return True
    except ConnectionRefusedError:
        return False
    