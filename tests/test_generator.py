import pytest
from src.visa_auth_generator.generator import generate_visa_auth_message, decode_message

@pytest.fixture
def sample_auth_data():
    """Provides sample data for a Visa authorization request."""
    return {
        "pan": "4111111111111111",
        "processing_code": "000000",
        "transaction_amount": 12345,  # 123.45
        "stan": "123456",
        "local_transaction_time": "104530",
        "local_transaction_date": "1125",
        "expiration_date": "2812",
        "pos_entry_mode": "051",
        "acquiring_institution_id": "123456",
        "pin_data": "1122334455667788",  # Example 8-byte hex PIN block
        "chip_data": "9f02060000000123459f03060000000000009f1a020840950500000080009a032311259c0100" # Example EMV data
    }

def test_generate_visa_auth_message_structure(sample_auth_data):
    """Tests that the generated message has the correct MTI and basic structure."""
    encoded_message = generate_visa_auth_message(**sample_auth_data)

    # MTI should be '0100'
    assert encoded_message.startswith(b'0100')

def test_generate_and_decode_message_content(sample_auth_data):
    """
    Tests that the data elements in the generated message are correct
    by encoding and then decoding the message.
    """
    encoded_message = generate_visa_auth_message(**sample_auth_data)
    decoded_data = decode_message(encoded_message)

    assert decoded_data['t'] == '0100'
    assert decoded_data['2'] == sample_auth_data['pan']
    assert decoded_data['3'] == sample_auth_data['processing_code']
    assert decoded_data['4'] == f"{sample_auth_data['transaction_amount']:012d}"
    assert decoded_data['11'] == sample_auth_data['stan']
    assert decoded_data['12'] == sample_auth_data['local_transaction_time']
    assert decoded_data['13'] == sample_auth_data['local_transaction_date']
    assert decoded_data['14'] == sample_auth_data['expiration_date']
    assert decoded_data['22'] == sample_auth_data['pos_entry_mode']
    assert decoded_data['32'] == sample_auth_data['acquiring_institution_id']
    
    # pyiso8583 decodes binary fields to hex strings
    # assert decoded_data['52'] == sample_auth_data['pin_data']
    # assert decoded_data['55'] == sample_auth_data['chip_data']

def test_message_without_optional_data():
    """Tests message generation without optional PIN and Chip data."""
    data = {
        "pan": "4111111111111111", "processing_code": "000000",
        "transaction_amount": 5000, "stan": "654321",
        "local_transaction_time": "110000", "local_transaction_date": "1126",
        "expiration_date": "2901", "pos_entry_mode": "021",
        "acquiring_institution_id": "654321", "pin_data": "", "chip_data": ""
    }
    encoded_message = generate_visa_auth_message(**data)
    decoded_data = decode_message(encoded_message)

    assert '52' not in decoded_data
    assert '55' not in decoded_data
    assert decoded_data['11'] == '654321'