'''
Created on 1 Jan 2020

@author: codimoc
'''

import argparse
import sys
from secretwallet.utils.dbutils import has_secret, get_secret, insert_secret, list_secrets,\
                                       update_secret, delete_secret, delete_secrets
from secretwallet.constants import parameters
from secretwallet.session.service import start_my_session
from secretwallet.session.client import get_session_password, set_session_password, stop_service, is_connected
import secretwallet.utils.password_manager as pm

class Parser(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='The Secrets manager',
            usage='''secretwallet <command> [<args>]

The list of secretwallet commands are:
   set             Insert a new secret
   get             Retrieves a secret
   delete          Remove a secret
   list            list all secretwallet in a given domain
   query           query secretwallet based on a condition
   reconf          change an existing configuration
   session         (testing) start a session to store the memorable password between consecutive calls
   client          (testing) retrieves the memorable password from the running session
   help            print the main help page 
   ....
   
For individual help type:
secretwallet <command> -h
''')
        parser.add_argument('command',
                            choices=['set','get','delete','list','query','reconf','help','session','client'],
                            help='Subcommand to run')
        self._parser = parser
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print('Unrecognized command')
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()
                
        
    def set(self):
        #TODO: manage memorable password
        parser = argparse.ArgumentParser(
            description='Insert a new secret',
            prog='secretwallet set')
        #required arguments
        parser.add_argument('-d',
                            dest='domain',
                            required=True,
                            help='The domain (category) of the secret')
        parser.add_argument('-a',
                        dest='access',
                        required=True,
                        help='The sub=domain (sub-category or access) of the secret')
        #optional arguments
        parser.add_argument('-u',
                            '--uid',
                            help='The login id for a given access')
        parser.add_argument('-p',
                            '--pwd',
                            help='The password for a given access')
        parser.add_argument('-ik',
                            '--info_key',
                            help='The key in an information map')
        parser.add_argument('-iv',
                            '--info_value',
                            help='The value in an information map')                       
        args = parser.parse_args(sys.argv[2:])
        #TODO: replace with logging
        print('Running set with arguments %s' % args)
        if args.info_key is None or args.info_value is None:
            info = None
        else:
            info = {args.info_key :args.info_value}                       
        try:
            memorable, need_session = pm.get_memorable_password(True)
            if not has_secret(args.domain, args.access): 
                insert_secret(args.domain, args.access, args.uid, args.pwd, info , memorable)
            else:
                update_secret(args.domain, args.access, args.uid, args.pwd, args.info_key, args.info_value, memorable)
            if need_session:
                start_my_session(memorable, parameters.get_session_lifetime(), parameters.get_session_timeout())
        except Exception as e:
            #TODO: log error instead
            print(repr(e))
        
    def get(self):
        #TODO: manage memorable password
        parser = argparse.ArgumentParser(
            description='Retrieves a secret',
            prog='secretwallet get')
        #required arguments
        parser.add_argument('-d',
                            dest='domain',
                            required=True,
                            help='The domain (category) of the secret')
        parser.add_argument('-a',
                        dest='access',
                        required=True,
                        help='The sub=domain (sub-category or access) of the secret')
        args = parser.parse_args(sys.argv[2:])
        #TODO: replace with logging
        print('Running get with arguments %s' % args)
        try:
            memorable, need_session = pm.get_memorable_password(False)
            display_secret(get_secret(args.domain, args.access, memorable))
            if need_session:
                start_my_session(memorable, parameters.get_session_lifetime(), parameters.get_session_timeout())            
        except Exception as e:
            #TODO: log error
            print(repr(e))
            
    def delete(self):
        parser = argparse.ArgumentParser(
            description='Removes a secret',
            prog='secretwallet delete')
        #required arguments
        parser.add_argument('-d',
                            dest='domain',
                            required=True,
                            help='The domain (category) of the secret')
        parser.add_argument('-a',
                            dest ='access',
                            help='The sub=domain (sub-category or access) of the secret')
        args = parser.parse_args(sys.argv[2:])
        #TODO: replace with logging
        print('Running delete with arguments %s' % args)
        try:
            if args.access is not None:
                confirm_delete([(args.domain, args.access)])
                delete_secret(args.domain, args.access)
            else:
                secrets = list_secrets(args.domain)
                confirm_delete(secrets)
                delete_secrets(secrets)
        except Exception as e:
            #TODO: log error
            print(repr(e))            

    def list(self):
        parser = argparse.ArgumentParser(
            description='Lists all secretwallet in a given domain',
            prog='secretwallet list')
        #optional arguments
        parser.add_argument('-d',
                            '--domain',
                            help='The domain (category) of the secretwallet. If not given all secretwallet are returned')
        args = parser.parse_args(sys.argv[2:])
        #TODO: replace with logging
        print('Running list with arguments %s' % args)
        try:
            secrets = list_secrets(args.domain)
            print("<%-19s:<access>"%'domain>')
            for s in secrets:
                print("%-20s:%s"%s)
        except Exception as e:
            #TODO: log error
            print(repr(e))                    
        
    def help(self):
        self._parser.print_help()
        
        
    #TODO: Below here is experimental. Remove at the end    
    def session(self):
        parser = argparse.ArgumentParser(
            description='Starts a secretwallet session service',
            prog='secretwallet session')
        #optional arguments
        parser.add_argument('-l',
                            dest = 'lifetime',
                            type = int,
                            help='The lifetime in seconds of the session',
                            default = parameters.get_session_lifetime())
        parser.add_argument('-t',
                            dest = 'timeout',
                            type = int,
                            help='The timeout in seconds for the session value',
                            default = parameters.get_session_timeout())
        parser.add_argument('-v',
                            dest = 'value',
                            help='The value to store in the session',
                            default='not set')                
        args = parser.parse_args(sys.argv[2:])
        #TODO: replace with logging
        print('Starting a secret wallet session with parameters %s'%args)
        try:
            start_my_session(args.value, args.lifetime, args.timeout)
        except Exception as e:
            #TODO: log error instead
            print(repr(e))
            
            
    def client(self):
        parser = argparse.ArgumentParser(
            description='Starts a secretwallet client',
            prog='secretwallet client')
        #optional arguments
        parser.add_argument('-a',
                            dest = 'action',
                            choices=['get','set','stop','test'],
                            help='The client action',
                            default = 'get')
        parser.add_argument('-v',
                            dest = 'value',
                            help='The value to store in the session',
                            default='not set')                
        args = parser.parse_args(sys.argv[2:])
        #TODO: replace with logging
        print('Starting a secret wallet client with parameters %s'%args)
        try:
            if args.action == 'get':
                print(get_session_password())
            elif args.action == 'set':
                set_session_password(args.value)
            elif args.action == 'stop':
                stop_service()
            elif args.action == 'test':
                if is_connected():
                    print('connected')
                else:
                    print('not connected')                
        except Exception as e:
            #TODO: log error instead
            print(repr(e))                           
            
            
def display_secret(secret):
    "Print a secret in a fixed format"
    print("**********************************************************")
    print("Secret id:")
    print(f"domain              : {secret['domain']}")
    print(f"access              : {secret['access']}")
    print("\nSecret credentials:")
    print(f"login               : {secret['uid']}")
    print(f"password            : {secret['pwd']}")
    if 'info' in secret: 
        print("\nSecret extra info:")
        for k,v in secret['info'].items():
            print(f"{k:20}: {v}")
    print(f"\nLast updated        : {secret['timestamp']}")
    print("**********************************************************")
    
    
def confirm_delete(secrets):
    "Confirm secets to delete"
    print("**********************************************************")
    print("Secrets to delete:")
    print("<%-19s:<access>"%'domain>')
    for d,a in secrets:
        print("%-20s:%s"%(d,a))    
    print("**********************************************************")
    answ = input("\nDo you want to delete these secrets (yes|no) ")
    if not answ.lower().startswith('y'):
        exit(1)    
        