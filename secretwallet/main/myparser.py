'''
Created on 1 Jan 2020

@author: gualtiero
'''

import argparse
import sys
from secretwallet.main.configuration import set_configuration
from secretwallet.utils.dbutils import has_secret,get_secret, insert_secret, list_secrets, update_secret, delete_secret
from secretwallet.utils.cryptutils import encrypt_key


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
   help            print the main help page 
   ....
   
For individual help type:
secretwallet <command> -h
''')
        parser.add_argument('command',
                            choices=['set','get','delete','list','query','reconf','help'],
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
        parser.add_argument('-m',
                        dest='memorable',
                        required=True,
                        help='The memorable password to be used for encryption/decryption')    
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
        print('Running set with arguments %s' % args)
        if args.info_key is None or args.info_value is None:
            info = None
        else:
            info = {args.info_key :args.info_value}                       
        try:
            if not has_secret(args.domain, args.access): 
                insert_secret(args.domain, args.access, args.uid, args.pwd, info , args.memorable)
            else:
                update_secret(args.domain, args.access, args.uid, args.pwd, info, args.memorable)
        except Exception as e:
            print(repr(e))
        
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
        parser.add_argument('-m',
                        dest='memorable',
                        required=True,
                        help='The memorable password to be used for encryption/decryption')    
        args = parser.parse_args(sys.argv[2:])
        print('Running get with arguments %s' % args)
        try:
            print(get_secret(args.domain, args.access, args.memorable))
        except Exception as e:
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
                        dest='access',
                        required=True,
                        help='The sub=domain (sub-category or access) of the secret')
        args = parser.parse_args(sys.argv[2:])
        print('Running delete with arguments %s' % args)
        try:
            delete_secret(args.domain, args.access)
        except Exception as e:
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
        print('Running list with arguments %s' % args)
        try:
            secrets = list_secrets(args.domain)
            print("<%-19s:<access>"%'domain>')
            for s in secrets:
                print("%-20s:%s"%s)
        except Exception as e:
            print(repr(e))                    
        
    def help(self):
        self._parser.print_help()        