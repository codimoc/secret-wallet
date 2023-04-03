import pytest
from secretwallet.constants import parameters
import secretwallet.storage.aws_dynamo as ad

@pytest.fixture
def set_up_table():
    table = ad.AWSDynamoTable(parameters.get_table_name(), parameters.get_profile_name())
    yield table
    
def test_has_table(set_up_table):
    table = set_up_table #here i get the table from the set_up
    assert table.has_table()
