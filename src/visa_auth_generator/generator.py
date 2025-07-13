import json
from pyiso8583.iso8583 import ISO8583
from pyiso8583.specs import default_ascii as spec

# Customize the spec for specific fields if needed.
# For example, DE 55 for chip data is often binary.
# For simplicity in this example, we'll treat it as ASCII hex.
spec['55']['ContentType'] = 'b'

def generate_visa_auth_message(
    pan: str,
    processing_code: str,
    transaction_amount: int,
    stan: str,
    local_transaction_time: str,
    local_transaction_date: str,
    expiration_date: str,
    pos_entry_mode: str,
    acquiring_institution_id: str,
    pin_data: str,
    chip_data: str
) -> bytes:
    """
    Generates a Visa ISO 8583 authorization request message (0100).

    Args:
        pan (str): Primary Account Number (DE 2).
        processing_code (str): Processing Code (DE 3).
        transaction_amount (int): Transaction Amount in cents (DE 4).
        stan (str): Systems Trace Audit Number (DE 11).
        local_transaction_time (str): Time, Local Transaction (HHMMSS) (DE 12).
        local_transaction_date (str): Date, Local Transaction (MMDD) (DE 13).
        expiration_date (str): Date, Expiration (YYMM) (DE 14).
        pos_entry_mode (str): Point of Service Entry Mode (DE 22).
        acquiring_institution_id (str): Acquiring Institution ID (DE 32).
        pin_data (str): PIN Data (hex-encoded) (DE 52).
        chip_data (str): ICC (Chip) Data (hex-encoded) (DE 55).

    Returns:
        bytes: The encoded ISO 8583 message.
    """
    iso_message = ISO8583()
    iso_message.set_mti('0100')

    # Populate Data Elements
    iso_message.set_element('2', pan)
    iso_message.set_element('3', processing_code)
    iso_message.set_element('4', f"{transaction_amount:012d}") # 12 digits, zero-padded
    iso_message.set_element('11', stan)
    iso_message.set_element('12', local_transaction_time)
    iso_message.set_element('13', local_transaction_date)
    iso_message.set_element('14', expiration_date)
    iso_message.set_element('22', pos_entry_mode)
    iso_message.set_element('32', acquiring_institution_id)

    # PIN Data (DE 52) - should be a hex string representing binary data
    if pin_data:
        iso_message.set_element('52', bytes.fromhex(pin_data))

    # ICC (Chip) Data (DE 55) - should be a hex string representing TLV data
    if chip_data:
        iso_message.set_element('55', bytes.fromhex(chip_data))

    # The library automatically calculates and adds the bitmap
    encoded_message, _ = iso_message.build(spec=spec)

    return encoded_message

def decode_message(encoded_message: bytes) -> dict:
    """Decodes an ISO 8583 message for verification."""
    iso_message = ISO8583()
    iso_message.parse(encoded_message, spec=spec)
    return json.loads(iso_message.json())