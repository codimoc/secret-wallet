from multiprocessing.connection import Client
from secretwallet.constants import parameters, is_posix
from secretwallet.utils.logging import get_logger

logger = get_logger(__name__)

def get_session_password():
    if not is_posix():
        raise NotImplementedError("Client/Server daemons not supported on this system")
    logger.info("Retrieving session password")
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'get','password':None})
    r = conn.recv()
    conn.close()
    return r['status'],r['password']

def set_session_password(pwd):
    if not is_posix():
        return    
    logger.info("Setting session password")
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'set','password':pwd})
    r = conn.recv()
    conn.close()
    logger.debug(r['status'])

def stop_service():
    if not is_posix():
        return
    logger.info("Stopping the service")
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())        
    conn.send({'action':'stop','password':None})
    r = conn.recv()
    conn.close()
    logger.debug(r['status'])
    
def is_connected():
    if parameters.is_in_shell():
        return False #the secret_wallet shell has a different way to keep the password
    if not is_posix():
        return False  #only posix systems support daemons in the way required
    try:
        get_session_password()
        return True
    except ConnectionRefusedError:
        return False
    
