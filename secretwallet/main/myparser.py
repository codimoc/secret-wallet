'''
Created on 1 Jan 2020

@author: codimoc
'''

import argparse
import contextlib
import json
import shlex
import sys

import readline
from secretwallet.constants import parameters
from secretwallet.main.configuration import list_configuration, get_configuration, set_configuration_data
from secretwallet.session.client import get_session_password, set_session_password, stop_service, is_connected
from secretwallet.session.service import start_my_session
from secretwallet.utils.cryptutils import encrypt_key
from secretwallet.utils.dbutils import has_secret, get_secret, insert_secret, list_secrets, update_secret, \
                                       update_secret_info_dictionary, delete_secret, delete_secrets, rename_secret, \
                                       reconf_memorable, reconf_salt_key, query_secrets_by_field, query_secrets_by_pattern, \
                                       get_all_secrets
from secretwallet.utils.logging import get_logger

import pkg_resources as pkg
import secretwallet.utils.ioutils as iou
import secretwallet.utils.password_manager as pm


logger = get_logger(__name__, parameters.get_log_level())
parameters.register_logger(__name__, logger)

usage_bash = '''secret_wallet <command> [<args>]

The list of secretwallet commands are:
   set             Insert a new secret
   get             Retrieves a secret
   delete          Remove a secret
   rename          rename a secret
   list            list all secrets in a given domain
   conf            manage the configuration file
   query           query secrets based on a condition
   qget            query based on pattern, and retrieval of chosen secret
   reconf          change an existing configuration
   session         (testing) start a session to store the memorable password between consecutive calls
   client          (testing) retrieves the memorable password from the running session
   help            print the main help page
   version         the version of this package
   shell           starts a secret_wallet sheel for interctive queries
   dump            dump all secrets to a file in text format
   save            save all secrets to a json file for backup and safe keeping (to be re-loaded)
   load            reload all secrets from a json file (backup and restore)
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
   qget            query based on pattern, and retrieval of chosen secret
   reconf          change an existing configuration
   help            print the main help page
   version         the version of this package
   quit            terminate the interactive shell
   dump            dump all secrets to a file in text format
   save            save all secrets to a json file for backup and safe keeping (to be re-loaded)
   load            reload all secrets from a json file (backup and restore)
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
                                     'query','qget','reconf','help','session','client',
                                     'version', 'shell', 'dump', 'save','load'],
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
        """
            Add or change a secret in the wallet. This could be an entire new secret, with all the information passed inline
            or an update of an existing secret. What is set with this command determines the content of a secret, identified
            by the domain, access pair. Key values pairs, as defined by the -ik and -iv options, can be added incrementally
            by multiple calls to the set command.
        """
        parser = argparse.ArgumentParser(
            description=self.set.__doc__,
            prog='secret_wallet set')
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
        """
            Retrieves the information stored inside a secret, as identified by the domain, access pair. These two fields need
            to be passed by using the -d and -a options
        """
        parser = argparse.ArgumentParser(
            description=self.get.__doc__,
            prog='secret_wallet get')
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
        """
            Deletes an existing secret, as identified by the domain, access pair. These two fields can
            be passed by using the -d and -a options. If only the domain is given, all secrets for that domain
            are deleted. When the -ik option is given with a key name, the corresponding entry
            in the info dictionary is removed, only if both domain and access are given and they identify an existing secret
        """
        parser = argparse.ArgumentParser(
                              description=self.delete.__doc__,
                              prog='secret_wallet delete')
        #required arguments
        parser.add_argument('-d',
                            dest='domain',
                            required=True,
                            help='The domain (category) of the secret')
        parser.add_argument('-a',
                            dest ='access',
                            help='The sub=domain (sub-category or access) of the secret')
        parser.add_argument('-ik',
                            '--info_key',
                            help='The key in an information map')

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Running delete with arguments %s' % args)
        try:
            if args.domain is not None and args.access is not None and args.info_key is not None:
                iou.confirm_delete_key(args.domain, args.access, args.info_key)
                sec = get_secret(args.domain, args.access, None, None, False) #no decryption
                info = sec['info']
                del info[args.info_key]
                update_secret_info_dictionary(args.domain, args.access, info)
            elif args.domain is not None and args.access is not None:
                iou.confirm_delete([(args.domain, args.access)])
                delete_secret(args.domain, args.access)
            else:
                secrets = list_secrets(args.domain)
                iou.confirm_delete(secrets)
                delete_secrets(secrets)
        except Exception as e:
            iou.my_output(repr(e))

    def rename(self):
        """
           Renames a secret, as identified by the domain, access pair. A new domain name can be passed with the -nd option and a new access
           name can be passed with the -na option. Both domain and access can be changed at the same time or on their own.
        """
        parser = argparse.ArgumentParser(
            description=self.rename.__doc__,
            prog='secret_wallet rename')
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
        """
           List a set of secrets. With no option passed, all secrets are returned. Alternatively it is possible to filter secrets by
           passing a domain name: all secrets for that domain will be returned.
        """
        parser = argparse.ArgumentParser(
            description=self.list.__doc__,
            prog='secret_wallet list')
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
        """
           Searches for secrets containig a given subtext in either their domain or access names, or both. By using the explicit -d and -a
           options, it is possible to limit the search to domain names or access names only. Alternatively it is possible to pass a subtext
           without any specification in front (i.e. without -d or -a) and the search of that pattern will include both domain and access names.
        """
        parser = argparse.ArgumentParser(
            description=self.query.__doc__,
            prog='secret_wallet query')
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
                            help='A pattern that is searched both in the domain and the access field')

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

    def qget(self):
        """
           Searches for secrets containig a given subtext in their domain or access names. Once a list of secrets
           that match the given pattern is found, thre secrets are tagged with a progressive number and the user can
           select the one to retrieve and display.
        """
        parser = argparse.ArgumentParser(
            description=self.qget.__doc__,
            prog='secret_wallet qget')

        parser.add_argument('pattern',
                            default=None,
                            help='A pattern that is searched both in the domain and the access field')

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Query secrets with arguments %s' % args)
        try:
            if (args.pattern is not None):
                secrets = query_secrets_by_pattern(args.pattern)
            sec = iou.get_secret_by_idx("List of secrets", secrets)
            if sec is None:
                return
            try:
                memorable, need_session = pm.get_memorable_password(False)
                iou.display_secret(get_secret(sec[0], sec[1], memorable))
                if need_session:
                    start_my_session(memorable, parameters.get_session_lifetime(), parameters.get_session_timeout())
            except Exception as e:
                iou.my_output(repr(e))

        except Exception as e:
            iou.my_output(repr(e))

    def conf(self):
        """
           Configures some parameters for this application. It is possible to list all parameters with the -l option,
           or to configure the timeout and lifetime (in seconds) or the log level.
           The timeout is the amount of time in seconds along which the memorable password is remembered without been re-asked.
           The lifetime determines the lifetime of the background process that manages the temporary storage of
           the memorable password. The value of the lifetime parameter should be bigger than the password timeout.
           The logging level is one of debug, info, warning, critical, error or fatal.
        """
        parser = argparse.ArgumentParser(
            description=self.conf.__doc__,
            prog='secret_wallet conf')
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
        parser.add_argument('-ll',
                            '--loglevel',
                            dest = 'loglevel',
                            help='Logging level. One of debug, info, warning, critical, error or fatal')

        args = iou.my_parse(parser,sys.argv[2:])
        if args is None:
            return

        iou.my_output('Running conf with arguments %s' % args)
        try:
            if (args.list):
                list_configuration()
            else:
                conf = get_configuration()
                if args.timeout is not None and args.timeout >=0:
                    conf['session_timeout']=args.timeout
                if args.lifetime is not None and args.lifetime >=0:
                    conf['session_lifetime']=args.lifetime
                if args.loglevel is not None:
                    if args.loglevel.lower() in ['debug', 'info', 'warning', 'critical', 'error','fatal']:
                        conf['log_level'] = args.loglevel.lower()
                    else:
                        iou.my_output(f"The passed log level {args.loglevel.lower()} is not valid")
                set_configuration_data(conf)
        except Exception as e:
            iou.my_output(repr(e))

    def reconf(self):
        """
           Reconfigures either the memorable or the device password. All secrets will be re-encryted with the changed password.
           It is not possible to change both passwords at the same time. Depending on the size of the wallet, this operation
           might take some time. A backup of the old table is also performed.
        """
        parser = argparse.ArgumentParser(
            description=self.reconf.__doc__,
            prog='secret_wallet reconf')
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

        try:
            if args.memorable and args.device:
                print("You can't reconfigure both memorable and device password at the same time")
            elif args.memorable:
                iou.my_output("You are reconfiguring the memorable password")
                if is_connected():
                    stop_service()
                iou.display_reconfiguration_warning()

                iou.my_output('***Enter the existing memorable password***')
                old_memorable, _ = pm.get_memorable_password(False)
                iou.my_output('***Set the new memorable password***')
                new_memorable, _ = pm.get_memorable_password(True)
                reconf_memorable(list_secrets(None), old_memorable, new_memorable, True)
            elif args.device:
                iou.my_output("You are reconfiguring the device password")
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
                                     'query','qget','reconf','help','session','quit',
                                     'version', 'dump', 'save'],
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
        """
           Starts a background session for keeping track of the memorable password for a short while. This is only for testing
           since this process is started automatically when needed by the secret_wallet. The lifetime parameter sets the lifetime of
           the session in seconds, the timeout the time in second for which the memorable password is kept, and the value is what
           has to be remembered
        """
        parser = argparse.ArgumentParser(
            description=self.session.__doc__,
            prog='secret_wallet session')
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
        """ Client command to invoke the background session. This is for testing only. The action allows to get the session value,
            set the value, stop the background session and test if it is running
        """
        parser = argparse.ArgumentParser(
            description=self.client.__doc__,
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

    def dump(self):
        " Dumps all secrets to a flat file , designated by the option -f, or the console when not specified."
        parser = argparse.ArgumentParser(
            description=self.dump.__doc__,
            prog='secretwallet dump')
        #optional arguments
        parser.add_argument('-f',
                            dest='file',
                            required=False,
                            help='The output file. If it is not specified it dumps to the console (default system out stream)')

        args = iou.my_parse(parser,sys.argv[2:])

        iou.my_output('Starting a secret wallet dump with parameters %s'%args)
        try:
            memorable, need_session = pm.get_memorable_password(False)

            secrets = get_all_secrets(memorable)
            if (args.file is not None):
                with open(args.file,'a') as f:
                    with contextlib.redirect_stdout(f):
                        iou.display_all_secrets(secrets) #send to file
            else:
                iou.display_all_secrets(secrets) #send to the console

            #here start the session (at the end so that we can daemonize)
            if need_session:
                start_my_session(memorable, parameters.get_session_lifetime(), parameters.get_session_timeout())
        except Exception as e:
            iou.my_output(repr(e))

    def save(self):
        """ Save all secrets to a json file , designated by the option -f, or the console when not specified.
        This file can be used for safe-keeping and reload, via the load function
        """
        parser = argparse.ArgumentParser(
            description=self.save.__doc__,
            prog='secretwallet save')
        #optional arguments
        parser.add_argument('-f',
                            dest='file',
                            required=False,
                            help='The output file. If it is not specified it outputs the json structure to the console (default system out stream)')

        args = iou.my_parse(parser,sys.argv[2:])

        iou.my_output('Starting a secret wallet save with parameters %s'%args)
        try:
            memorable, need_session = pm.get_memorable_password(False)

            secrets = get_all_secrets(memorable)
            if (args.file is not None):
                with open(args.file,'w') as f:
                    with contextlib.redirect_stdout(f):
                        json.dump(secrets, f) #send to file
            else:
                iou.my_output(json.dumps(secrets), with_logging=False)

            #here start the session (at the end so that we can daemonize)
            if need_session:
                start_my_session(memorable, parameters.get_session_lifetime(), parameters.get_session_timeout())
        except Exception as e:
            iou.my_output(repr(e))

    def load(self):
        """Reload secrets, previously stored in a json file after a backup operation (save action).
        It requires a json file as input, as specified with the -f option."""
        parser = argparse.ArgumentParser(
            description=self.load.__doc__,
            prog='secretwallet load')
        #optional arguments
        parser.add_argument('-f',
                            dest='file',
                            required=True,
                            help='The input file in json format, containing the backed-up secrets.')

        args = iou.my_parse(parser,sys.argv[2:])
        iou.my_output('Starting a secret wallet load with parameters %s'%args)
        try:
            memorable, need_session = pm.get_memorable_password(True)

            with open(args.file,'r') as f:
                secrets = json.load(f)
                for secret in secrets:
                    domain = secret["domain"]
                    access = secret["access"]
                    if not has_secret(domain, access):
                        iou.my_output(f"inserting secret (domain:{domain}, access:{access})")
                        insert_secret(domain, access, secret["uid"], secret["pwd"], secret["info"] , memorable, timestamp=secret["timestamp"])

            #here start the session (at the end so that we can daemonize)
            if need_session:
                start_my_session(memorable, parameters.get_session_lifetime(), parameters.get_session_timeout())
        except Exception as e:
            iou.my_output(repr(e))
