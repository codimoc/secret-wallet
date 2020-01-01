'''
Created on 1 Jan 2020

@author: gualtiero
'''

import argparse
import sys


class Parser(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='The Secrets manager',
            usage='''secrets <command> [<args>]

The list of secrets commands are:
   set             Insert a new secret
   get             Retrieves a secret
   list            list all secrets in a given domain
   query           query secrets based on a condition
   init            create the initial configuration for a client device
   reconf          change an existing configuration
   help            print the main help page 
   ....
   
For individual help type:
secrets <command> -h
''')
        parser.add_argument('command', help='Subcommand to run')
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
        
    def set(self):
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
                            help='The login if for a given access')
        parser.add_argument('-p',
                            '--pwd',
                            help='The password for a given access')
        parser.add_argument('-i',
                            '--info',
                            help='An information field for a given access')               
        args = parser.parse_args(sys.argv[2:])
        print('Running set with arguments %s' % args)
        
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
        
    def help(self):
        self._parser.print_help()        