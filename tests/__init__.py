import os

from secretwallet.constants import parameters
from secretwallet.main.configuration import get_configuration


path = os.path.dirname(__file__)
conf_file = os.path.join(path,'data','test_integration.json')
conf_data = get_configuration(conf_file)
parameters.set_data(conf_data)
