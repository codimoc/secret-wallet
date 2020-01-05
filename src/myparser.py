'''
Created on 1 Jan 2020

@author: gualtiero
'''

import argparse
import sys
import cryptutils as cu
import dbutils as du


class Parser(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='The Secrets manager',
            usage='''secrets <command> [<args>]

The list of secrets commands are:
   set             Insert a new secret
   get             Retrieves a secret
   delete          Remove a secret
   list            list all secrets in a given domain
   query           query secrets based on a condition
   init            create the initial configuration for a client device
   reconf          change an existing configuration
   help            print the main help page 
   ....
   
For individual help type:
secrets <command> -h
''')
        parser.add_argument('command',
                            choices=['set','get','delete','list','query','init','reconf','help'],
                            help='Subcommand to run')
        self._parser = parser
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print('Unrecognized command')
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()
        
    def init(self):
        parser = argparse.ArgumentParser(
            description='Create the initial configuration on the client device',
            prog='secrets init')
        #required arguments
        parser.add_argument('-c',
                            dest='cfg_pwd',
                            required=True,
                            help='The configuration password to encrypt the secret key')
        args = parser.parse_args(sys.argv[2:])
        print('Running init with arguments %s' % args)
        try:
            cu.configure(args.cfg_pwd)
        except RuntimeError as e:
            print(e)
        
        
    def set(self):
        #Need to check if it exists already, and it is an update or a create

        parser = argparse.ArgumentParser(
            description='Insert a new secret',
            prog='secrets set')
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
        try:
            if not du.has_secret(args.domain, args.access):                
                du.insert_secret(args.domain, args.access, args.uid, args.pwd, {args.info_key :args.info_value}, args.memorable)
            else:
                du.update_secret(args.domain, args.access, args.uid, args.pwd, args.info_key, args.info_value, args.memorable)
        except Exception as e:
            print(repr(e))
        
    def get(self):
        parser = argparse.ArgumentParser(
            description='Retrieves a secret',
            prog='secrets get')
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
            print(du.get_secret(args.domain, args.access, args.memorable))
        except Exception as e:
            print(repr(e))
            
    def delete(self):
        parser = argparse.ArgumentParser(
            description='Removes a secret',
            prog='secrets delete')
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
            du.delete_secret(args.domain, args.access)
        except Exception as e:
            print(repr(e))            

    def list(self):
        parser = argparse.ArgumentParser(
            description='Lists all secrets in a given domain',
            prog='secrets list')
        #optional arguments
        parser.add_argument('-d',
                            '--domain',
                            help='The domain (category) of the secrets. If not given all secrets are returned')
        args = parser.parse_args(sys.argv[2:])
        print('Running list with arguments %s' % args)
        try:
            secrets = du.list_secrets(args.domain)
            print("<%-19s:<access>"%'domain>')
            for s in secrets:
                print("%-20s:%s"%s)
        except Exception as e:
            print(repr(e))                    
        
    def help(self):
        self._parser.print_help()        