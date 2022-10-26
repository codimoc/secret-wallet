import datetime
from multiprocessing import Process
from multiprocessing.connection import Client, Listener
from time import sleep

from secretwallet.constants import parameters, is_posix
from secretwallet.utils.logging import get_logger

logger = get_logger(__name__, parameters.get_log_level())
parameters.register_logger(__name__, logger)

def session_listener(seed, timeout):
    """ Session service function with an initial value as a seed
    input: seed    the initial value stored in the session
           timeout the validity period of the session value (in seconds
    """
    logger.info("Listener starts")
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
                req.clear()
            elif 'action' in req and req['action'] == 'get':
                if (datetime.datetime.now() - serv.start_time).total_seconds() < serv.pwd_timeout:
                    conn.send({'status':'fresh','password':serv.password})
                    serv.start_time = datetime.datetime.now()
                else:
                    serv.password =  None
                    conn.send({'status':'stale','password':None})
                req.clear()
            elif 'action' in req and req['action'] == 'stop':
                logger.debug("Goodbye from listener")
                conn.send({'status':'terminated','password':None})
                req.clear()
                break #break here to stop the server
            elif 'action' in req and req['action'] == 'ping':
                logger.debug("Ping request from listener")
                conn.send({'status':'OK','password':None})
                req.clear()
            else:
                conn.send({'status':'bad command','password':None})
                req.clear()
    logger.info("Listener ends")


def session_sweeper(lifetime):
    "The process that will kill the session daemon eventually"
    logger.info("sweeper starts")
    sleep(lifetime)
    conn = Client(parameters.get_session_address(), authkey=parameters.get_session_connection_password())
    conn.send({'action':'stop','password':None})
    ret = conn.recv()
    logger.debug(ret['status'])
    logger.info("Sweeper ends")

def my_session(value, lifetime, timeout):
    p = Process(target=session_sweeper, args=(lifetime,))
    q = Process(target=session_listener, args=(value, timeout))
    p.daemon = True
    q.daemon = True

    p.start()
    q.start()
    #keep track of process pids
    parameters.set_listener_pid(q.pid)
    parameters.set_sweeper_pid(p.pid)

    p.join()
    q.join()

    p.terminate()
    q.terminate()

def start_my_session(value, lifetime, timeout):
    if is_posix() and not parameters.is_in_shell():
        import daemon
        with daemon.DaemonContext():
            my_session(value, lifetime, timeout)
    else: #Windows or other system don't support daemons in the way required
        pass

