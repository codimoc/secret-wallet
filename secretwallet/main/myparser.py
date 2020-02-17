'''
Created on 1 Jan 2020

@author: codimoc
'''

import argparse
import sys
import pkg_resources as pkg
from secretwallet.utils.dbutils import has_secret, get_secret, insert_secret, list_secrets,\
                                       update_secret, delete_secret, delete_secrets, rename_secret
from secretwallet.main.configuration import list_configuration, get_configuration, set_configuration_data
from secretwallet.constants import parameters
from secretwallet.session.service import start_my_session
from secretwallet.session.client import get_session_password, set_session_password, stop_service, is_connected
import secretwallet.utils.password_manager as pm
from email.policy import default

class Parser(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='The Secrets manager',
            usage='''secretwallet <command> [<args>]

The list of secretwallet commands are:
   set             Insert a new secret
   get             Retrieves a secret
   delete          Remove a secret
   rename          rename a secret
   list            list all secrets in a given domain
   conf            manage the configuration file
   query           query secrets based on a condition
   reconf          change an existing configuration
   session         (testing) start a session to store the memorable password between consecutive calls
   client          (testing) retrieves the memorable password from the running session
   help            print the main help page
   version         the version of this package
   ....
   
For individual help type:
secretwallet <command> -h
''')        
        parser.add_argument('command',
                            action='store',
                            choices=['set','get','delete', 'rename', 'list', 'conf',
                                     'query','reconf','help','session','client', 'version'],
                            help='Command to run')
        self._parser = parser
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            my_output('Unrecognized command')
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
        my_output('Running set with arguments %s' % args)
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
            my_output(repr(e))
        
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
        my_output('Running get with arguments %s' % args)
        try:
            memorable, need_session = pm.get_memorable_password(False)
            display_secret(get_secret(args.domain, args.access, memorable))
            if need_session:
                start_my_session(memorable, parameters.get_session_lifetime(), parameters.get_session_timeout())            
        except Exception as e:
            my_output(repr(e))
            
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
        my_output('Running delete with arguments %s' % args)
        try:
            if args.access is not None:
                confirm_delete([(args.domain, args.access)])
                delete_secret(args.domain, args.access)
            else:
                secrets = list_secrets(args.domain)
                confirm_delete(secrets)
                delete_secrets(secrets)
        except Exception as e:
            my_output(repr(e))            

    def rename(self):
        parser = argparse.ArgumentParser(
            description='Renames a secret',
            prog='secretwallet rename')
        #required arguments
        parser.add_argument('-d',
                            dest='domain',
                            required=True,
                            help='The domain (category) of the secret')
        parser.add_argument('-a',
                            dest ='access',
                            required=True,
                            help='The sub=domain (sub-category or access) of the secret')
        parser.add_argument('-nd',
                            dest='new_domain',
                            default = None,
                            help='The new domain')
        parser.add_argument('-na',
                            dest ='new_access',
                            default = None,
                            help='The new asset')        
        args = parser.parse_args(sys.argv[2:])
        my_output('Running rename with arguments %s' % args)
        try:
            if args.new_domain is None and args.new_access is None:
                my_output("No new keys have been passed", True)
            elif args.new_domain == args.domain and args.new_access == args.access:
                my_output("Both new values are the same as the originals: nothing to do", True)
            elif not has_secret(args.domain, args.access):
                my_output("Could not find the secret to rename", True)                                    
            else:
                if args.new_domain is None:
                    args.new_domain = args.domain
                if args.new_access is None:
                    args.new_access = args.access
                confirm_rename([(args.domain, args.access)])                                    
                rename_secret(args.domain, args.access, args.new_domain, args.new_access)
        except Exception as e:
            my_output(repr(e))

    def list(self):
        parser = argparse.ArgumentParser(
            description='Lists all secrets in a given domain',
            prog='secretwallet list')
        #optional arguments
        parser.add_argument('-d',
                            '--domain',
                            help='The domain (category) of the secrets. If not given all secrets are returned')
        args = parser.parse_args(sys.argv[2:])
        my_output('Running list with arguments %s' % args)
        try:
            secrets = list_secrets(args.domain)
            display_list("List of secrets", secrets)
        except Exception as e:
            my_output(repr(e))
            
    def conf(self):
        parser = argparse.ArgumentParser(
            description='Manage the configuration parameters',
            prog='secretwallet conf')
        #optional arguments
        parser.add_argument('-l',
                            '--list',
                            action = 'store_true',
                            default = False,
                            help='List the existing configuration parameters')
        parser.add_argument('-to',
                            '--timeout',
                            dest = 'timeout',
                            type = int,
                            default = -1,
                            help='Session time-out in seconds')
        parser.add_argument('-lf',
                            '--lifetime',
                            dest = 'lifetime',
                            type = int,
                            default = -1,
                            help='Session lifetime in seconds')                
        args = parser.parse_args(sys.argv[2:])
        my_output('Running conf with arguments %s' % args)
        try:
            if (args.list):
                list_configuration()
            elif args.timeout >=0 or args.lifetime >=0:
                conf = get_configuration()
                if args.timeout >=0:
                    conf['session_timeout']=args.timeout
                if args.lifetime >=0:
                    conf['session_lifetime']=args.lifetime
                set_configuration_data(conf)
            else:
                pass
        except Exception as e:
            my_output(repr(e))                                
        
    def help(self):
        self._parser.print_help()
        
    def version(self):
        print("secret-wallet-codimoc version %s"%pkg.get_distribution('secret-wallet-codimoc').version)
                       
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
        my_output('Starting a secret wallet session with parameters %s'%args)
        try:
            start_my_session(args.value, args.lifetime, args.timeout)
        except Exception as e:
            my_output(repr(e))
            
            
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
        my_output('Starting a secret wallet client with parameters %s'%args)
        try:
            if args.action == 'get':
                my_output(get_session_password())
            elif args.action == 'set':
                set_session_password(args.value)
            elif args.action == 'stop':
                stop_service()
            elif args.action == 'test':
                if is_connected():
                    my_output('connected')
                else:
                    my_output('not connected')                
        except Exception as e:
            my_output(repr(e))                           
            
            
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
    
    
def display_list(message, secrets):
    field_lenght = max([len(x[0]) for x in secrets])+5
    format_header = f"<%-{field_lenght-1}s:<access>"
    format_record = f"%-{field_lenght}s:%s"
    print("**********************************************************")
    print(f"{message}:")
    print(format_header%'domain>')
    for d,a in secrets:
        print(format_record%(d,a))
    print("**********************************************************")        
    
def confirm_delete(secrets):
    "Confirm secrets to delete"
    display_list("Secrets to delete", secrets)
    answ = my_input("\nDo you want to delete these secrets (yes|no) ")
    if not answ.lower().startswith('y'):
        exit(1)
        
def confirm_rename(secrets):
    "Confirm secret to rename"
    display_list("Secret to rename", secrets)
    answ = my_input("\nDo you want to rename this secret (yes|no) ")
    if not answ.lower().startswith('y'):
        exit(1)            
        
def my_input(question):
    "Mockable input function"
    return input(question)

def my_output(message, exit=False):
    "Mockable output function"
    #TODO: add logging here
    print(message)
    if exit:
        exit(1)