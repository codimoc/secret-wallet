import daemon
import datetime
from multiprocessing import Process
from multiprocessing.connection import Client, Listener
from time import sleep
from secretwallet.constants import parameters


def session_listener(seed, timeout):
    """ Session service function with an initial value as a seed
    input: seed    the initial value stored in the session
           timeout the validity period of the session value (in seconds 
    """
    #TODO: replace with logging
    print("Listener starts")
    serv = Listener(parameters.get_session_address(), authkey=parameters.get_session_connection_password())
    serv.password = seed
    serv.pwd_timeout = timeout
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
                #TODO: replace with logging
                print("Goodbye from listener")
                conn.send({'status':'terminated','password':None})
                break
            else:
                conn.send({'status':'bad command','password':None})
    #TODO: replace with logging
    print("Listener ends")
            

def session_sweeper(lifetime):
    "The process that will kill the session daemon eventually"
    #TODO: replace with logging
    print("sweeper starts")
    sleep(lifetime)
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())    
    conn.send({'action':'stop','password':None})
    ret = conn.recv()
    #TODO: replace with logging
    print(ret['status'])
    print("sweeper ends")
            
def my_session(value, lifetime, timeout):
    p = Process(target=session_sweeper, args=(lifetime,))           
    q = Process(target=session_listener, args=(value, timeout))
    p.daemon = True
    q.daemon = True
    
    p.start()
    q.start()
    
    p.join()
    q.join()
    
def start_my_session(value, lifetime, timeout):             
    with daemon.DaemonContext():
        my_session(value, lifetime, timeout)        
    