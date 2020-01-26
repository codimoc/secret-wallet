from getpass import getpass
from password_strength import PasswordPolicy
from secretwallet.constants import parameters, PWD_LENGTH, PWD_NUMBERS, PWD_SPECIAL, PWD_UPPER, PWD_ATTEMPTS
import secretwallet.session.client as sc
from secretwallet.session.service import start_my_session

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
        p1 = getpass(f"{prompt}-First entry  :")
        explanation = explain(p1)
        if explanation is not None:
            print(explanation)
            num_attempts -= 1
            continue
        p2 = getpass(f"{prompt}-Verification :")
        if p1 != p2:
            print("The two passwords are different, try again")
            num_attempts -= 1
            continue
        return p1 
    print("Too many attempts at entering a valid password. Goodbye!")
    exit(1)
    
def get_password_untested(prompt):
    return getpass(f"{prompt} :")
    
def get_memorable_password(tested = False):
    memorable = None
    if sc.is_connected():
        res = sc.get_session_password()
        if res[0] == 'fresh':
            return res[1]
        else:
            if tested:
                memorable = get_password("Enter the memorable password", PWD_ATTEMPTS)
            else:
                memorable = get_password_untested("Enter the memorable password")
            sc.set_session_password(memorable)
            return memorable
    else: #session not running
        if tested:
            memorable = get_password("Enter the memorable password", PWD_ATTEMPTS)
        else:
            memorable = get_password_untested("Enter the memorable password")
        start_my_session(memorable, parameters.get_session_lifetime(), parameters.get_session_timeout())
        return memorable