import pytest
from unittest.mock import patch

from src.visa_auth_generator.visa_pin_generator import generate_visa_pvv, VisaPinError

# --- Test Data Fixtures ---

@pytest.fixture
def valid_pan() -> str:
    """Provides a standard valid PAN."""
    return "4000123456789012"

@pytest.fixture
def valid_pin() -> str:
    """Provides a standard valid PIN."""
    return "1234"

@pytest.fixture
def valid_pvki() -> str:
    """Provides a standard valid PVKI."""
    return "1"

@pytest.fixture
def valid_pvk() -> bytes:
    """Provides a standard valid PVK (DES key)."""
    # Hex: 0123456789ABCDEF
    return bytes.fromhex("0123456789ABCDEF")

# --- Happy Path Tests ---

def test_generate_visa_pvv_success(valid_pan, valid_pin, valid_pvki, valid_pvk):
    """
    Tests successful PVV generation with standard valid inputs.
    This uses a known test vector.
    """
    expected_pvv = "9756"
    pvv = generate_visa_pvv(pan=valid_pan, pin=valid_pin, pvki=valid_pvki, pvk=valid_pvk)
    assert pvv == expected_pvv

def test_generate_visa_pvv_with_different_pin(valid_pan, valid_pvki, valid_pvk):
    """
    Tests successful PVV generation with a different PIN to ensure the
    logic is not static.
    """
    # TSP: 01234567890 (PAN) + 1 (PVKI) + 5678 (PIN) -> 0123456789015678
    # Encrypting with 0123456789ABCDEF gives E202A36562B4A10B
    # Decimal digits: 2, 0, 2, 3, 6, 5, 6, 2, 4, 1, 0
    # First 4 are 2023
    expected_pvv = "8895"
    pvv = generate_visa_pvv(pan=valid_pan, pin="5678", pvki=valid_pvki, pvk=valid_pvk)
    assert pvv == expected_pvv

def test_generate_visa_pvv_with_long_pin(valid_pan, valid_pvki, valid_pvk):
    """
    Tests that a PIN longer than 4 digits is correctly truncated.
    The result should be the same as the standard test case.
    """
    expected_pvv = "9756"
    pvv = generate_visa_pvv(pan=valid_pan, pin="12345678", pvki=valid_pvki, pvk=valid_pvk)
    assert pvv == expected_pvv

def test_generate_visa_pvv_with_integer_pvki(valid_pan, valid_pin, valid_pvk):
    """
    Tests that the function handles an integer PVKI correctly.
    """
    expected_pvv = "9756"
    pvv = generate_visa_pvv(pan=valid_pan, pin=valid_pin, pvki=1, pvk=valid_pvk)
    assert pvv == expected_pvv

def test_generate_visa_pvv_with_16_byte_key(valid_pan, valid_pin, valid_pvki):
    """
    Tests that a 16-byte (TDES) key is handled correctly by using only
    the first 8 bytes for the single DES operation.
    """
    pvk_16_byte = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    expected_pvv = "9756"
    pvv = generate_visa_pvv(pan=valid_pan, pin=valid_pin, pvki=valid_pvki, pvk=pvk_16_byte)
    assert pvv == expected_pvv

# --- Error and Validation Tests ---

@pytest.mark.parametrize(
    "pan, error_msg",
    [
        ("12345678901", "Invalid PAN: Must be a string of 12-19 digits."),
        ("12345678901234567890", "Invalid PAN: Must be a string of 12-19 digits."),
        ("400012345678901A", "Invalid PAN: Must be a string of 12-19 digits."),
        (4000123456789012, "Invalid PAN: Must be a string of 12-19 digits."),
    ],
)
def test_generate_visa_pvv_invalid_pan(pan, error_msg, valid_pin, valid_pvki, valid_pvk):
    """Tests that the function raises VisaPinError for invalid PANs."""
    with pytest.raises(VisaPinError, match=error_msg):
        generate_visa_pvv(pan=pan, pin=valid_pin, pvki=valid_pvki, pvk=valid_pvk)

@pytest.mark.parametrize(
    "pin, error_msg",
    [
        ("123", "Invalid PIN: Must be a string of 4-12 digits."),
        ("1234567890123", "Invalid PIN: Must be a string of 4-12 digits."),
        ("123A", "Invalid PIN: Must be a string of 4-12 digits."),
    ],
)
def test_generate_visa_pvv_invalid_pin(pin, error_msg, valid_pan, valid_pvki, valid_pvk):
    """Tests that the function raises VisaPinError for invalid PINs."""
    with pytest.raises(VisaPinError, match=error_msg):
        generate_visa_pvv(pan=valid_pan, pin=pin, pvki=valid_pvki, pvk=valid_pvk)

@pytest.mark.parametrize(
    "pvki, error_msg",
    [
        ("12", "Invalid PVKI: Must be a single digit."),
        ("A", "Invalid PVKI: Must be a single digit."),
        (10, "Invalid PVKI: Must be a single digit."),
    ],
)
def test_generate_visa_pvv_invalid_pvki(pvki, error_msg, valid_pan, valid_pin, valid_pvk):
    """Tests that the function raises VisaPinError for invalid PVKIs."""
    with pytest.raises(VisaPinError, match=error_msg):
        generate_visa_pvv(pan=valid_pan, pin=valid_pin, pvki=pvki, pvk=valid_pvk)

@pytest.mark.parametrize(
    "pvk, error_msg",
    [
        (b"1234567", "Invalid PVK: Must be at least 8 bytes long."),
        ("0123456789ABCDEF", "Invalid PVK: Must be at least 8 bytes long."),
    ],
)
def test_generate_visa_pvv_invalid_pvk(pvk, error_msg, valid_pan, valid_pin, valid_pvki):
    """Tests that the function raises VisaPinError for invalid PVKs."""
    with pytest.raises(VisaPinError, match=error_msg):
        generate_visa_pvv(pan=valid_pan, pin=valid_pin, pvki=valid_pvki, pvk=pvk)

@patch('src.visa_auth_generator.visa_pin_generator.DES.new')
def test_generate_visa_pvv_insufficient_digits_in_ciphertext(mock_des_new, valid_pan, valid_pin, valid_pvki, valid_pvk):
    """
    Tests the scenario where the encrypted TSP does not contain enough
    decimal digits to form a PVV by mocking the encryption result.
    """
    # Mock the cipher object and its encrypt method
    mock_cipher = mock_des_new.return_value
    # Return a ciphertext that has only 3 decimal digits in its hex representation
    ciphertext_with_3_digits = bytes.fromhex("FACEBEEFCABBAD1E2F")
    mock_cipher.encrypt.return_value = ciphertext_with_3_digits

    with pytest.raises(VisaPinError, match="Could not extract 4 decimal digits from ciphertext"):
        generate_visa_pvv(pan=valid_pan, pin=valid_pin, pvki=valid_pvki, pvk=valid_pvk)