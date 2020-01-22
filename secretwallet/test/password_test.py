from secretwallet.utils.password_manager import explain

def test_short_password():
    pwd = 'mamma'
    assert 'password length' in explain(pwd)
    
def test_missing_numbers_in_password():
    pwd = 'Mamm@ePapp@'
    assert 'minimum number of numbers in password' in explain(pwd)    
    
def test_missing_uppercase_password():
    pwd = 'mamm@3papp@'
    assert 'minimum number of upper-case characters' in explain(pwd)
    
def test_missing_special_password():
    pwd = 'Mamma3pappa'
    assert 'minimum number of special characters' in explain(pwd)
    
def test_good_password():
    pwd = 'Mamm@3pappa'
    assert explain(pwd) is None    