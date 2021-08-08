import getpass
import logging
from secretwallet.utils.logging import get_logger
from secretwallet.constants import parameters

logger = get_logger(__name__, logging.DEBUG)

def display_list(message, secrets):
    field_lenght = max([len(x[0]) for x in secrets], default=0)+5
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

def my_output(message, want_exit=False):
    "Mockable output function"
    print(message)
    if want_exit:
        exit(1)

def my_getpass(question):
    "Mockable getpass function"
    return getpass(question)    

def my_parse(parser, args):
    try:
        return parser.parse_args(args)
    except SystemExit:
        if parameters.is_in_shell():
            parser.print_usage()
            return None
        else:
            raise

class MockableInput:
    def __init__(self,inputs) -> None:
        "Passes a sets of inputs to be replayed"

        #internal generator function  
        def generator(inputs) -> str:
            while len(inputs) > 0:
                yield inputs.pop(0)
            return

        self.__generator = generator(inputs)

    def __call__(self, question:str) -> str:
        input = self.__generator.__next__()
        logger.debug(f"{question}: {input}")
        return input


def display_reconfiguration_warning():
    "Display a warning when reconfiguring the system"
    print("*******************************************************************")
    print("""
  You are performing a reconfiguration of the secrets' remote 
  table. This is because you are either changing the memorable-
  or the device password. This will result in all of your
  secrets being re-encrypted with the new password. You will
  not be able to retrieve them with the old keys.
  This operation takes time, depending on how large is the
  table. Be patient!
  A backup of the original table is performed, in case you need 
  to roll back the table.
  You can manage your time-stamped backups from the AWS
  Management console or using the secret-wallet command line.
          """)
    print("*******************************************************************") 
    answ = input("\nDo you want to go ahead? (yes|no) ")
    if answ.lower().startswith('y'):
        return
    else:
        exit(1)                          
            
            
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
