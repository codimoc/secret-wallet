import daemon
import datetime
from multiprocessing import Process
from multiprocessing.connection import Client, Listener
from time import sleep
from secretwallet.constants import SESSION_ADDRESS, SESSION_PWD, SESSION_LIFETIME, SESSION_TIMEOUT


def session(seed):
    """ Session service function with an initial value as a seed
    input: seed the initial value stored in the session
    """
    serv = Listener(SESSION_ADDRESS, authkey=SESSION_PWD)
    serv.password = seed
    serv.pwd_timeout = SESSION_TIMEOUT
    serv.start_time = datetime.datetime.now()
    serv.origin_time = datetime.datetime.now()    
    while True:    
        with serv.accept() as conn: 
            try:
                req = conn.recv()
            except EOFError:
                break
            if 'action' in req and req['action'] == 'set':
                serv.password = req['password']
                serv.start_time = datetime.datetime.now()
                conn.send({'status':'done','password':serv.password})
            elif 'action' in req and req['action'] == 'get':
                if (datetime.datetime.now() - serv.start_time).total_seconds() < serv.pwd_timeout:
                    conn.send({'status':'fresh','password':serv.password})
                    serv.start_time = datetime.datetime.now()
                else:
                    serv.password =  None
                    conn.send({'status':'stale','password':None})
            elif 'action' in req and req['action'] == 'stop':
                #TODO: add logging
                print("Goodbye from listener")
                conn.send({'status':'terminated','password':None})
                break
            else:
                conn.send({'status':'bad command','password':None})
            

def sweeper():
    "The process that will kill the session daemon eventually"
    sleep(SESSION_LIFETIME)
    conn = Client(SESSION_ADDRESS, authkey=SESSION_PWD)    
    conn.send({'action':'stop','password':None})
    #TODO: add logging
    print(conn.recv())
    
def start_service(seed):
    """ Starts the session service
    input: seed the initial value stored in the session
    """
    p = Process(target=sweeper())
    p.daemon = True
    p.start()    

    #this should be at the end                
    with daemon.DaemonContext():
        session(seed)    