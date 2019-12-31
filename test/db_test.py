'''
Created on 30 Dec 2019

@author: gualtiero
'''
import pytest
import os
import cryptutils as cu
import dbutils as du 

@pytest.fixture
def set_up():
    path = os.path.dirname(__file__)
    conf_file = os.path.join(path,'data','.secrets','test.json')
    yield conf_file
    
    if os.path.exists(conf_file):
        os.remove(conf_file)
        os.rmdir(os.path.dirname(conf_file))

def test_insert_delete_login(set_up):
    conf_file = set_up
    c_pwd = u"passwd"
    m_pwd = u"memorabile"
    secret_uid = u"me@home"
    secret_pwd = u"ciao mamma"
    domain = u"my_domain" 
    access = u"my_access"
    ns = du.count_secrets()
    cu.configure(c_pwd, conf_file)
    try:        
        du.insert_secret_login(domain, access, secret_uid, secret_pwd, m_pwd, conf_file)
        assert ns+1 == du.count_secrets()
    finally:
        du.delete_secret(domain, access)
        assert ns == du.count_secrets()
        
def test_insert_select_compare_login(set_up):
    conf_file = set_up
    c_pwd = u"passwd"
    m_pwd = u"memorabile"
    secret_uid = u"me@home"
    secret_pwd = u"ciao mamma"
    domain = u"my_domain" 
    access = u"my_access"
    cu.configure(c_pwd, conf_file)
    try:        
        du.insert_secret_login(domain, access, secret_uid, secret_pwd, m_pwd, conf_file)
        res = du.get_secret_login(domain, access, m_pwd, conf_file)
        assert secret_uid == res['uid']
        assert secret_pwd == res['pwd']
    finally:
        du.delete_secret(domain, access)
        
def test_insert_select_compare_info(set_up):
    conf_file = set_up
    c_pwd = u"passwd"
    m_pwd = u"memorabile"
    secret_info = u"hello 123"
    domain = u"my_domain" 
    access = u"my_access"
    cu.configure(c_pwd, conf_file)
    try:        
        du.insert_secret_info(domain, access, secret_info, m_pwd, conf_file)
        res = du.get_secret_info(domain, access, m_pwd, conf_file)
        assert secret_info == res['info']
    finally:
        du.delete_secret(domain, access)        
        