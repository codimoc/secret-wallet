import os

from secretwallet.constants import parameters, DB_AWS_DYNAMO, DB_LOCAL_SQLITE
from secretwallet.main.configuration import get_configuration
import secretwallet.utils.dbutils as du


path = os.path.dirname(__file__)
conf_file = os.path.join(path,'data','test_integration.json')
conf_data = get_configuration(conf_file)
parameters.set_data(conf_data)

#here create all test tables with different storage types and then reset to default

#local storage
parameters.set_storage_type(DB_LOCAL_SQLITE)
du.create_table(parameters.get_table_name())

#aws
parameters.set_storage_type(DB_AWS_DYNAMO)
du.create_table(parameters.get_table_name())