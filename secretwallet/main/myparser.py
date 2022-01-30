'''
Created on 1 Jan 2020

@author: codimoc
'''

import argparse
import readline
import shlex
import sys

from secretwallet.constants import parameters
from secretwallet.main.configuration import list_configuration, get_configuration, set_configuration_data
from secretwallet.session.client import get_session_password, set_session_password, stop_service, is_connected
from secretwallet.session.service import start_my_session
from secretwallet.utils.cryptutils import encrypt_key
from secretwallet.utils.dbutils import has_secret, get_secret, insert_secret, list_secrets, \
                                       update_secret, delete_secret, delete_secrets, rename_secret, \
                                       reconf_memorable, reconf_salt_key, query_secrets_by_field, query_secrets_by_pattern
from secretwallet.utils.logging import get_logger                                    

import pkg_resources as pkg
import secretwallet.utils.ioutils as iou 
import secretwallet.utils.password_manager as pm


logger = get_logger(__name__)

usage_bash = '''secret_wallet <command> [<args>]

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
   shell           starts a secret_wallet sheel for interctive queries
   ....
   
For individual help type:
secretwallet <command> -h
'''

usage_shell = '''<command> [<args>]

The list of secretwallet commands are:
   set             Insert a new secret
   get             Retrieves a secret
   delete          Remove a secret
   rename          rename a secret
   list            list all secrets in a given domain
   conf            manage the configuration file
   query           query secrets based on a condition
   reconf          change an existing configuration
   help            print the main help page
   version         the version of this package
   quit            terminate the interactive shell
   ....
   
For individual help type:
<command> -h
'''

class Parser(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='The Secrets manager',
            usage=usage_bash)        
        parser.add_argument('command',
                            action='store',
                            choices=['set','get','delete', 'rename', 'list', 'conf',
                                     'query','reconf','help','session','client',
                                     'version', 'shell'],
                            help='Command to run')
        self._parser = parser
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            iou.my_output('Unrecognized command')
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()
                
        
    def set(self):
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

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Running set for domain %s and access %s' %(args.domain,args.access))
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
            iou.my_output(repr(e))
        
    def get(self):
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

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Running get with arguments %s' % args)
        try:
            memorable, need_session = pm.get_memorable_password(False)
            iou.display_secret(get_secret(args.domain, args.access, memorable))
            if need_session:
                start_my_session(memorable, parameters.get_session_lifetime(), parameters.get_session_timeout())            
        except Exception as e:
            iou.my_output(repr(e))
            
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

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Running delete with arguments %s' % args)
        try:
            if args.access is not None:
                iou.confirm_delete([(args.domain, args.access)])
                delete_secret(args.domain, args.access)
            else:
                secrets = list_secrets(args.domain)
                iou.confirm_delete(secrets)
                delete_secrets(secrets)
        except Exception as e:
            iou.my_output(repr(e))            

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
        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return
        
        iou.my_output('Running rename with arguments %s' % args)
        try:
            if args.new_domain is None and args.new_access is None:
                iou.my_output("No new keys have been passed", True)
            elif args.new_domain == args.domain and args.new_access == args.access:
                iou.my_output("Both new values are the same as the originals: nothing to do", True)
            elif not has_secret(args.domain, args.access):
                iou.my_output("Could not find the secret to rename", True)                                    
            else:
                if args.new_domain is None:
                    args.new_domain = args.domain
                if args.new_access is None:
                    args.new_access = args.access
                iou.confirm_rename([(args.domain, args.access)])                                    
                rename_secret(args.domain, args.access, args.new_domain, args.new_access)
        except Exception as e:
            iou.my_output(repr(e))

    def list(self):
        parser = argparse.ArgumentParser(
            description='Lists all secrets in a given domain',
            prog='secretwallet list')
        #optional arguments
        parser.add_argument('-d',
                            '--domain',
                            help='The domain (category) of the secrets. If not given all secrets are returned')

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Running list with arguments %s' % args)
        try:
            secrets = list_secrets(args.domain)
            iou.display_list("List of secrets", secrets)
        except Exception as e:
            iou.my_output(repr(e))
            
    def query(self):
        parser = argparse.ArgumentParser(
            description='Query or filter the list of secrets by domain or access name',
            prog='secretwallet query')
        #optional arguments
        parser.add_argument('-d',
                            '--domain',
                            default=None,
                            help='A substring to query the domains. Only secrets with this substring in their domain are returned')
        parser.add_argument('-a',
                            '--access',
                            default=None,
                            help='A substring to query the access. Only secrets with this substring in their access are returned')
        
        parser.add_argument('pattern',
                            nargs='?',
                            default=None,
                            help='A pattern that is search both in the domain and the access field')

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Query secrets with arguments %s' % args)
        try:
            if (args.pattern is not None):
                secrets = query_secrets_by_pattern(args.pattern)
            else:
                secrets = query_secrets_by_field(args.domain, args.access)
            iou.display_list("List of secrets", secrets)
        except Exception as e:
            iou.my_output(repr(e))            
            
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

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Running conf with arguments %s' % args)
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
            iou.my_output(repr(e))
            
    def reconf(self):
        parser = argparse.ArgumentParser(
            description='Change the secret encryption because of a change of memorable or device password',
            prog='secretwallet reconf')
        #optional arguments
        parser.add_argument('-m',
                            '--memorable',
                            action = 'store_true',
                            default = False,
                            help='Reconfigure secrets because of a change of memorable password')
        parser.add_argument('-d',
                            '--device',
                            action = 'store_true',
                            default = False,
                            help='Reconfigure secrets because of a change of device password')        

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Running reconf for domain %s and access %s' %(args.domain,args.access))
        try:
            if args.memorable:
                if is_connected():
                    stop_service()
                iou.display_reconfiguration_warning()
                
                iou.my_output('***Enter the existing memorable password***')
                old_memorable, _ = pm.get_memorable_password(False)                
                iou.my_output('***Set the new memorable password***')
                new_memorable, _ = pm.get_memorable_password(True)
                reconf_memorable(list_secrets(None), old_memorable, new_memorable, True)
            elif args.device:
                if is_connected():
                    stop_service()
                iou.display_reconfiguration_warning()
                
                iou.my_output('***Enter the existing memorable password***')
                old_memorable, _ = pm.get_memorable_password(False)                
                iou.my_output('***Set the new device password***')
                new_device, _ = pm.get_memorable_password(True)
                reconf_salt_key(list_secrets(None), old_memorable, new_device, True)
                
                #now pass it to the configuration file
                ekey = encrypt_key(new_device)
                cdata = get_configuration()
                cdata['key'] = ekey
                set_configuration_data(cdata)                                
        except Exception as e:
            iou.my_output(repr(e))                                            
        
    def help(self):
        self._parser.print_help()
        
    def version(self):
        print("secret-wallet-codimoc version %s"%pkg.get_distribution('secret-wallet-codimoc').version)

    def shell(self):
        parser = argparse.ArgumentParser(
            description='Interactive secret_wallet shell',
            prog='secret_wallet shell')
        parser.add_argument('command',
                            action='store',
                            choices=['set','get','delete', 'rename', 'list', 'conf',
                                     'query','reconf','help','session','quit'],
                            help='Command to run inside the shell')
        iou.my_output('Starting a secret_wallet interactive shell. Type quit to quit, help for help')
        parameters.set_in_shell(True)
        #using readline for history of command line and other
        readline.parse_and_bind('tab: complete')
        readline.parse_and_bind('set editing-mode vi')
        while True: #this is the shell main loop
            cmd = iou.my_input(':> ')
            if cmd.lower().startswith('quit'):
                parameters.set_in_shell(False)
                break
            if cmd.lower().startswith('help'):
                iou.my_output(usage_shell, with_logging=False)
                continue
            tokens = shlex.split(cmd) #keep quoted test together
            try:
                args = parser.parse_args(tokens[:1])
            except SystemExit as e: #don't break the shell
                parameters.set_in_shell(False)
                iou.my_output("Wrong Input command!!")
                iou.my_output(usage_shell, with_logging=False)
                continue                
            if not hasattr(self, args.command):
                iou.my_output('Unrecognized command')
                iou.my_output(usage_shell, with_logging=False)
                continue
            # use dispatch pattern to invoke method with same name
            try:
                sys.argv=['secret_wallet'] + tokens  #append a first argument just for padding (could be anything)
                parameters.set_in_shell(True)
                getattr(self, args.command)()
                parameters.set_in_shell(False)
            except Exception as e: #don't break the shell
                parameters.set_in_shell(False)
                iou.my_output(repr(e))
                continue                   
                           
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

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Starting a secret wallet session with parameters %s'%args)
        try:
            start_my_session(args.value, args.lifetime, args.timeout)
        except Exception as e:
            iou.my_output(repr(e))
            
            
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

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return
    
        iou.my_output('Starting a secret wallet client with parameters %s'%args)
        try:
            if args.action == 'get':
                iou.my_output((get_session_password()[0],'***'))
            elif args.action == 'set':
                set_session_password(args.value)
            elif args.action == 'stop':
                stop_service()
            elif args.action == 'test':
                if is_connected():
                    iou.my_output('connected')
                else:
                    iou.my_output('not connected') 
        except Exception as e:
            iou.my_output(repr(e))
            