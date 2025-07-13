import pytest
from visa_auth_generator.emv import build_tlv, generate_arqc, create_chip_data

@pytest.fixture
def emv_test_data():
    """Provides common data for EMV tests."""
    return {
        "mdk_hex": "0123456789ABCDEFFEDCBA9876543210",
        "pan": "4111111111111111",
        "atc": 22,
        "transaction_details": {
            "amount": 12345,
            "currency_code": "0840",
            "country_code": "0840",
            "date": "231125",
        }
    }

def test_build_tlv():
    """Tests the TLV component builder."""
    tag = "9F02"
    value = "000000012345"
    expected_tlv = "9f0206000000012345"
    assert build_tlv(tag, value).lower() == expected_tlv

def test_generate_arqc_deterministic():
    """
    Tests ARQC generation with known inputs to ensure it's deterministic.
    """
    # Known 16-byte key and data
    session_key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    transaction_data = bytes.fromhex("00000001234500000000000008400000008000084023112500123456780016")
    
    arqc = generate_arqc(session_key, transaction_data)
    
    # The result should be 8 bytes long
    assert len(arqc) == 8
    # For a known input, the output should always be the same.
    # This pre-calculated value ensures the MAC logic is consistent.
    expected_arqc_hex = "d5e796f50cbd7343"
    assert arqc.hex() == expected_arqc_hex

def test_create_chip_data_structure_and_content(emv_test_data):
    """
    Tests the main chip data creation function for correct structure and content.
    """
    chip_data_hex = create_chip_data(**emv_test_data)

    # 1. Check if it's a valid hex string
    assert isinstance(chip_data_hex, str)
    try:
        bytes.fromhex(chip_data_hex)
    except ValueError:
        pytest.fail("create_chip_data did not return a valid hex string.")

    # 2. Check for presence of key tags
    assert "9f02" in chip_data_hex.lower()  # Amount
    assert "9a" in chip_data_hex.lower()    # Date
    assert "9f36" in chip_data_hex.lower()  # ATC
    assert "9f26" in chip_data_hex.lower()  # ARQC

    # 3. Check specific values
    amount_tlv = f"9f0206{emv_test_data['transaction_details']['amount']:012d}"
    assert amount_tlv in chip_data_hex.lower()

    atc_tlv = f"9f3602{emv_test_data['atc']:04x}"
    assert atc_tlv in chip_data_hex.lower()

def test_create_chip_data_invalid_mdk_length():
    """
    Tests that the function raises a ValueError for an MDK of incorrect length.
    """
    with pytest.raises(ValueError, match="MDK must be 16 bytes"):
        create_chip_data(
            mdk_hex="123456", # Invalid length (must be 32 hex chars)
            pan="4111111111111111",
            atc=1,
            transaction_details={"amount": 0, "currency_code": "0", "country_code": "0", "date": "0"}
        )