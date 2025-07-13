# from visa_auth_generator.generator import generate_visa_auth_message

from src.visa_auth_generator.generator import generate_visa_auth_message

def demo_iso8583_a():
    import pprint
    import iso8583
    from iso8583.specs import default_ascii as spec
    decoded = {'t': '0200'}
    encoded_raw, encoded = iso8583.encode(decoded, spec)
    encoded_raw
    pprint.pp(encoded)
    pprint.pp(decoded)

if __name__ == "__main__":

    # 1. Define the transaction data
    transaction_data = {
        "pan": "4111111111111111",
        "processing_code": "000000",
        "transaction_amount": 12345,  # Represents 123.45
        "stan": "123456",
        "local_transaction_time": "104530",
        "local_transaction_date": "1125",
        "expiration_date": "2812",
        "pos_entry_mode": "051", # Chip
        "acquiring_institution_id": "123456",
        "pin_data": "1122334455667788",  # 8-byte hex PIN block
        "chip_data": "9f02060000000123459f03060000000000009f1a020840950500000080009a032311259c0100" # Sample EMV data
    }

    # 2. Generate the message
    iso_message_bytes = generate_visa_auth_message(**transaction_data)

    # 3. Print the message (as a hex string for readability)
    print(f"Generated ISO 8583 Message (Hex): {iso_message_bytes.hex()}")
    print(f"Generated ISO 8583 Message (bytearray): {iso_message_bytes}")

    # demo_iso8583_a()

