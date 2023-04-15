import os

from secretwallet.constants import parameters
from secretwallet.main.configuration import get_configuration
import secretwallet.utils.dbutils as du


path = os.path.dirname(__file__)
conf_file = os.path.join(path,'data','test_integration.json')
conf_data = get_configuration(conf_file)
parameters.set_data(conf_data)
du.create_table(parameters.get_table_name())