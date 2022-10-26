from password_strength import PasswordPolicy
from secretwallet.constants import PWD_LENGTH, PWD_NUMBERS, PWD_SPECIAL, PWD_UPPER, PWD_ATTEMPTS, parameters
from secretwallet.utils.logging import get_logger

import secretwallet.session.client as sc
import secretwallet.utils.ioutils as iou


logger = get_logger(__name__, parameters.get_log_level())
parameters.register_logger(__name__, logger)

__policy = PasswordPolicy.from_names(length  = PWD_LENGTH,
                                   uppercase = PWD_UPPER,
                                   numbers   = PWD_NUMBERS,
                                   special   = PWD_SPECIAL )
__explanation = {f'Length({PWD_LENGTH})'   : f'The minimum password length is {PWD_LENGTH}',
                 f'Uppercase({PWD_UPPER})' : f'The minimum number of upper-case characters in password is {PWD_UPPER}',
                 f'Numbers({PWD_NUMBERS})' : f'The minimum number of numbers in password is {PWD_NUMBERS}',
                 f'Special({PWD_SPECIAL})' : f'The minimum number of special characters in password is {PWD_SPECIAL}',}

def validate(pwd):
    return __policy.test(pwd)

def explain(pwd):
    faults = validate(pwd) #it is a set
    if len(faults)==0:
        return None
    else:
        return __explanation[str(faults[0])]

def get_password(prompt, attempts):
    num_attempts = attempts
    while num_attempts >0:
        print(f"*** {num_attempts} attempts left ***")
        p1 = iou.my_getpass(f"{prompt}-First entry  :")
        explanation = explain(p1)
        if explanation is not None:
            print(explanation)
            num_attempts -= 1
            continue
        p2 = iou.my_getpass(f"{prompt}-Verification :")
        if p1 != p2:
            message = "The two passwords are different, try again"
            print(message)
            logger.error(message)
            num_attempts -= 1
            continue
        return p1
    message = "Too many attempts at entering a valid password. Goodbye!"
    print(message)
    logger.error(message)
    exit(1)

def get_password_untested(prompt):
    return iou.my_getpass(f"{prompt} :")

def get_memorable_password(tested = False):
    """Get the memorable password, either from the live session or from the client prompt.
    input:
    tested    a boolean flag. If true then the password strength is ensured
              and the password is checked against a second entry
    output:
    return a pair of values (memorable, need_session) where memorable is the
    memorable password and need_session is a flag that tells if a new session needs to be started.
    """
    memorable = None
    if parameters.is_in_shell(): #in shell mode the password is kept in memory in the parameters
        memorable = parameters.get_memorable_pwd()
        if memorable is not None:
            return (memorable, False)
        else:
            if tested:
                memorable = get_password("Enter the memorable password", PWD_ATTEMPTS)
            else:
                memorable = get_password_untested("Enter the memorable password")
            parameters.set_memorable_pwd(memorable)

            return (memorable, False)
    elif sc.is_connected(): #in bash shell the password is kept in a separate process
        res = sc.get_session_password()
        if res[0] == 'fresh':
            return (res[1], False)
        else:
            if tested:
                memorable = get_password("Enter the memorable password", PWD_ATTEMPTS)
            else:
                memorable = get_password_untested("Enter the memorable password")
            sc.set_session_password(memorable)
            return (memorable, False)
    else: #session not running
        if tested:
            memorable = get_password("Enter the memorable password", PWD_ATTEMPTS)
        else:
            memorable = get_password_untested("Enter the memorable password")
        return (memorable,True)