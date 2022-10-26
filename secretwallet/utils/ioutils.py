import getpass

from secretwallet.constants import parameters
from secretwallet.utils.logging import get_logger


logger = get_logger(__name__, parameters.get_log_level())
parameters.register_logger(__name__, logger)

def display_list(message, secrets):
    field_lenght = max([len(x[0]) for x in secrets], default=0)+5
    format_header = f"<%-{field_lenght-1}s: <access>"
    format_record = f"%-{field_lenght}s: %s"
    print("**********************************************************")
    print(f"{message}: ")
    print(format_header%'domain>')
    for d,a in secrets:
        print(format_record%(d,a))
    print("**********************************************************")

def display_numbered_list(message, secrets):
    field_lenght = max([len(x[0]) for x in secrets], default=0)+5
    format_header = f"%-7s: <%-{field_lenght-1}s: <access>"
    format_record = f"%-7d: %-{field_lenght}s: %s"
    print("**********************************************************")
    print(f"{message}: ")
    print(format_header%('<num>','domain>'))
    idx = 1;
    for d,a in secrets:
        print(format_record%(idx, d, a))
        idx += 1
    print("**********************************************************")

def get_secret_by_idx(message, secrets):
    display_numbered_list(message, secrets)
    while True:
        answ = my_input("\nWhich secret? Type the index number in the list above or 0 to quit:  ")
        try:
            idx = int(answ)
            if (idx==0):
                return None
            if idx > 0 and idx <= len(secrets):
                return secrets[idx-1]
            print("Index out of range. Please retry")
        except Exception as e:
            print(e)
            print("I need a number. Please retry")

def confirm_delete(secrets):
    "Confirm secrets to delete"
    display_list("Secrets to delete", secrets)
    answ = my_input("\nDo you want to delete these secrets (yes|no) ")
    if not answ.lower().startswith('y'):
        exit(1)

def confirm_delete_key(domain, access, key):
    "Confirm secrets to delete"
    answ = my_input(f"Do you want to delete the key {key} for domain {domain} and access {access}? (yes|no) ")
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

def my_output(message, want_exit=False, with_logging = True):
    "Mockable output function"
    if with_logging:
        logger.info(message)
    print(message)
    if want_exit:
        exit(1)

def my_getpass(question):
    "Mockable getpass function"
    return getpass.getpass(question)

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
        myinput = self.__generator.__next__()
        logger.debug(f"{question}: {input}")
        return myinput


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

def display_all_secrets(secrets):
    "Return a text representation of all the secrets in a readable format"
    for secret in secrets:
        display_secret(secret)
