import sys
from secretwallet.main import myparser
from secretwallet.main.configuration import load_configurations, make_configurations

def main():
    load_configurations()
    myparser.Parser()

def configure():
    make_configurations()
    
def shell():
    load_configurations()
    sys.argv=['secret_wallet','shell']
    myparser.Parser()
    
