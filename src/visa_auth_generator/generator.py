import json
import iso8583
from iso8583.specs import default_ascii as spec
import pprint

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
    # Build the message dictionary
    msg = {
        't': '0100',
        '2': pan,
        '3': processing_code,
        '4': f"{transaction_amount:012d}",
        '11': stan,
        '12': local_transaction_time,
        '13': local_transaction_date,
        '14': expiration_date,
        '22': pos_entry_mode,
        '32': acquiring_institution_id,
    }
    # if pin_data:
    #     msg['52'] = bytes.fromhex(pin_data)
    # if chip_data:
    #     msg['55'] = bytes.fromhex(chip_data)

    # Return the encoded message (bytearray)
    encoded_raw, encoded = iso8583.encode(msg, spec)
    pprint.pprint(msg)
    pprint.pprint(encoded)
    print(f"iso8583.pp decoded message")
    iso8583.pp(msg, spec)
    print(f"iso8583.pp decoded message")
    iso8583.pp(encoded, spec)

    return encoded_raw

def decode_message(encoded_message: bytes) -> dict:
    """Decodes an ISO 8583 message for verification."""
    msg, _ = iso8583.decode(encoded_message, spec)
    # Convert binary fields to hex for readability
    for k in ['52', '55']:
        if k in msg and isinstance(msg[k], (bytes, bytearray)):
            msg[k] = msg[k].hex()
    return msg